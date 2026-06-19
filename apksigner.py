#!/usr/bin/env python3
"""
APKSigner - Pure-Python APK v2 signing module.

Generates a fresh RSA-2048 key pair and self-signed X.509 certificate,
then zipaligns and signs any APK passed to sign() using APK Signature Scheme v2.

No third-party libraries or external tools are required.
"""

import os
import io
import struct
import hashlib
import zipfile
import zlib
import base64
from pathlib import Path


# ─────────────────────────────────────────────
# Minimal ASN.1 / DER helpers
# ─────────────────────────────────────────────

def _der_length(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    else:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])

def _der_tlv(tag, value):
    return bytes([tag]) + _der_length(len(value)) + value

def _der_sequence(*items):
    return _der_tlv(0x30, b"".join(items))

def _der_set(*items):
    return _der_tlv(0x31, b"".join(items))

def _der_integer(n):
    if isinstance(n, int):
        length = (n.bit_length() + 8) // 8
        raw = n.to_bytes(length, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        raw = raw.lstrip(b"\x00") or b"\x00"
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return _der_tlv(0x02, raw)
    return _der_tlv(0x02, n)

def _der_bit_string(data, unused_bits=0):
    return _der_tlv(0x03, bytes([unused_bits]) + data)

def _der_oid(dotted):
    parts = list(map(int, dotted.split(".")))
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
        else:
            enc = []
            while p:
                enc.append(p & 0x7F)
                p >>= 7
            enc.reverse()
            for i, b_ in enumerate(enc):
                body += bytes([b_ | (0x80 if i < len(enc) - 1 else 0)])
    return _der_tlv(0x06, body)

def _der_utf8string(s):
    return _der_tlv(0x0C, s.encode())

def _der_utctime(t):
    return _der_tlv(0x17, t.encode())

def _der_null():
    return b"\x05\x00"


# ─────────────────────────────────────────────
# ZIP helpers
# ─────────────────────────────────────────────

_LFH_SIGNATURE  = 0x04034b50
_LFH_FIXED_SIZE = 30
_CDFH_SIGNATURE = 0x02014b50
_EOCD_SIGNATURE = 0x06054b50
_ALIGN          = 4


def _dos_time(dt):
    return (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)

def _dos_date(dt):
    return ((dt[0] - 1980) << 9) | (dt[1] << 5) | dt[2]

def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def _compress(data: bytes, compress_type: int) -> bytes:
    if compress_type == zipfile.ZIP_STORED:
        return data
    return zlib.compress(data, 6)[2:-4]

def _version_needed(compress_type: int) -> int:
    return 20 if compress_type == zipfile.ZIP_DEFLATED else 10

_PAGE_ALIGN = 4096   # required for STORED .so when extractNativeLibs=false


def _padding_for_alignment(current_offset: int, filename_len: int,
                            align: int = _ALIGN) -> bytes:
    data_start_no_extra = current_offset + _LFH_FIXED_SIZE + filename_len
    remainder = data_start_no_extra % align
    if remainder == 0:
        return b""
    pad = align - remainder
    while pad < 4:
        pad += align
    return struct.pack("<HH", 0x0000, pad - 4) + b"\x00" * (pad - 4)

def _write_lfh(out: io.BytesIO, info: zipfile.ZipInfo,
               compress_type: int, crc: int,
               comp_size: int, uncomp_size: int,
               filename_b: bytes, extra: bytes) -> int:
    offset = out.tell()
    out.write(struct.pack(
        "<IHHHHHIIIHH",
        _LFH_SIGNATURE,
        _version_needed(compress_type),
        0,
        compress_type,
        _dos_time(info.date_time),
        _dos_date(info.date_time),
        crc,
        comp_size,
        uncomp_size,
        len(filename_b),
        len(extra),
    ))
    out.write(filename_b)
    out.write(extra)
    return offset

def _make_cdfh(info: zipfile.ZipInfo, compress_type: int,
               crc: int, comp_size: int, uncomp_size: int,
               filename_b: bytes, lfh_offset: int) -> bytes:
    return struct.pack(
        "<IHHHHHHIIIHHHHHII",
        _CDFH_SIGNATURE,
        _version_needed(compress_type),
        _version_needed(compress_type),
        0,
        compress_type,
        _dos_time(info.date_time),
        _dos_date(info.date_time),
        crc,
        comp_size,
        uncomp_size,
        len(filename_b),
        0,
        0,
        0,
        0,
        info.external_attr,
        lfh_offset,
    ) + filename_b

def _write_eocd(out: io.BytesIO, cd_entries: list):
    cd_offset = out.tell()
    cd_data   = b"".join(cd_entries)
    out.write(cd_data)
    out.write(struct.pack(
        "<IHHHHIIH",
        _EOCD_SIGNATURE,
        0, 0,
        len(cd_entries),
        len(cd_entries),
        len(cd_data),
        cd_offset,
        0,
    ))

def _find_eocd_offset(data: bytes) -> int:
    off = data.rfind(b"PK\x05\x06")
    if off == -1:
        raise ValueError("EOCD not found")
    return off

def _find_cd_offset(data: bytes) -> int:
    eocd_off = _find_eocd_offset(data)
    return struct.unpack_from("<I", data, eocd_off + 16)[0]


# ─────────────────────────────────────────────
# APK v2 length-prefix helpers
# ─────────────────────────────────────────────
#
# Every variable-length field in the v2 block is preceded by a
# uint32-LE length.  "Lists" are themselves length-prefixed and
# contain zero or more length-prefixed items.

def _lp(data: bytes) -> bytes:
    """Single length-prefixed value: uint32LE(len) || data."""
    return struct.pack("<I", len(data)) + data

def _lp_list(*items: bytes) -> bytes:
    """Length-prefixed list: uint32LE(total) || lp(item0) || lp(item1) ..."""
    return _lp(b"".join(_lp(i) for i in items))


# ─────────────────────────────────────────────
# APK v2 digest helpers
# ─────────────────────────────────────────────

_CHUNK_SIZE           = 1024 * 1024
_V2_BLOCK_MAGIC       = b"APK Sig Block 42"
_V2_SIGNATURE_ID      = 0x7109871a
_SIG_RSA_PKCS1_SHA256 = 0x0103


def _hash_chunk(chunk: bytes) -> bytes:
    """SHA-256( 0xa5 || uint32LE(len) || chunk )"""
    h = hashlib.sha256()
    h.update(b"\xa5")
    h.update(struct.pack("<I", len(chunk)))
    h.update(chunk)
    return h.digest()


def _hash_top_level(chunk_hashes: list) -> bytes:
    """SHA-256( 0x5a || uint32LE(count) || hash_0 || ... || hash_n )"""
    h = hashlib.sha256()
    h.update(b"\x5a")
    h.update(struct.pack("<I", len(chunk_hashes)))
    for ch in chunk_hashes:
        h.update(ch)
    return h.digest()


def _v2_content_digest(zip_entries: bytes, cd: bytes, eocd: bytes) -> bytes:
    """
    Compute the v2 content digest over the three ZIP sections.
    Each section is independently split into 1 MiB chunks.
    """
    all_hashes = []
    for section in (zip_entries, cd, eocd):
        chunks = [section[i:i + _CHUNK_SIZE]
                  for i in range(0, max(len(section), 1), _CHUNK_SIZE)]
        for chunk in chunks:
            all_hashes.append(_hash_chunk(chunk))
    return _hash_top_level(all_hashes)


# ─────────────────────────────────────────────
# APK Signing Block assembly
# ─────────────────────────────────────────────

def _assemble_signing_block(id_value_pairs: list) -> bytes:
    """
    id_value_pairs: list of (uint32 id, bytes value)

    APK Signing Block layout:
        uint64   size_of_block          (= total block size - 8)
        repeated:
            uint64   size_of_pair       (= 4 + len(value))
            uint32   id
            bytes    value
        uint64   size_of_block          (same value, repeated)
        bytes[16] magic
    """
    pairs_bytes = b""
    for pair_id, pair_val in id_value_pairs:
        pair_size    = 4 + len(pair_val)            # id (4) + value
        pairs_bytes += struct.pack("<Q", pair_size)
        pairs_bytes += struct.pack("<I", pair_id)
        pairs_bytes += pair_val

    # size_of_block = everything after the first uint64 up to and including magic
    # = len(pairs_bytes) + 8 (trailing size) + 16 (magic)
    size_of_block = len(pairs_bytes) + 8 + 16

    return (
        struct.pack("<Q", size_of_block) +
        pairs_bytes +
        struct.pack("<Q", size_of_block) +
        _V2_BLOCK_MAGIC
    )


# ─────────────────────────────────────────────
# APKSigner
# ─────────────────────────────────────────────

class APKSigner:
    """
    Pure-Python APK zipalign + v2 (APK Signature Scheme v2) signer.

    Pipeline when sign() is called:
        1. zipalign  — aligns every uncompressed entry to 4-byte boundaries
        2. v2 sign   — inserts APK Signing Block before the Central Directory

    No third-party libraries or external tools are required.
    """

    _OID_RSA             = "1.2.840.113549.1.1.1"
    _OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
    _OID_COMMON_NAME     = "2.5.4.3"
    _OID_ORG             = "2.5.4.10"
    _OID_COUNTRY         = "2.5.4.6"

    _SHA256_DER_PREFIX = bytes([
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ])

    def __init__(self, logger, bits: int = 2048):
        self.logger = logger
        self.logger.debug(f"Generating {bits}-bit RSA key pair…")
        self._n, self._e, self._d, self._p, self._q = self._generate_rsa_keypair(bits)
        self.logger.debug("Building self-signed X.509 certificate…")
        self._spki_der = self._build_spki()
        self._cert_der = self._build_x509_cert()

    # ── public API ────────────────────────────

    def sign(self, apk_path: str) -> str:
        """
        Zipalign then sign an APK using APK Signature Scheme v2.

        Args:
            apk_path: Path to the APK to process.

        Returns:
            Path of the newly aligned and signed APK.
        """
        apk_path = Path(apk_path)
        out_path = apk_path.with_stem(apk_path.stem + "_resigned")

        self.logger.debug("Zipaligning…")
        aligned = self._zipalign(apk_path)

        self.logger.debug("Signing with APK Signature Scheme v2…")
        signed = self._sign_v2(aligned)

        out_path.write_bytes(signed)
        self.logger.debug(f"Resigned APK written to: {out_path}")
        return str(out_path)

    # ── v2 signing ────────────────────────────

    def _sign_v2(self, apk_bytes: bytes) -> bytes:
        eocd_off = _find_eocd_offset(apk_bytes)
        cd_off   = struct.unpack_from("<I", apk_bytes, eocd_off + 16)[0]

        zip_entries = apk_bytes[:cd_off]
        cd_data     = apk_bytes[cd_off:eocd_off]
        eocd_orig   = apk_bytes[eocd_off:]

        # ── pass 1: build dummy block to learn its exact size ─────────────
        dummy_block  = self._build_v2_block(b"\x00" * 32)
        block_size   = len(dummy_block)

        # APK v2 spec: for content digest, EOCD.cd_offset = start of signing block = cd_off
        eocd_patched = bytearray(eocd_orig)
        struct.pack_into("<I", eocd_patched, 16, cd_off)

        # ── pass 2: real digest and real block ────────────────────────────
        digest       = _v2_content_digest(zip_entries, cd_data, bytes(eocd_patched))
        real_block   = self._build_v2_block(digest)

        assert len(real_block) == block_size, \
            "Block size changed between passes"

        # final EOCD patch (same offset, just being explicit)
        eocd_final = bytearray(eocd_orig)
        struct.pack_into("<I", eocd_final, 16, cd_off + len(real_block))

        return zip_entries + real_block + cd_data + bytes(eocd_final)

    def _build_v2_block(self, content_digest: bytes) -> bytes:
        """
        Build the complete APK Signing Block for a single v2 signer.

        signed-data:
            digests        lp-list[ lp(uint32(algo) || lp(digest)) ]
            certificates   lp-list[ lp(cert_der) ]
            attributes     lp-list[] (empty)

        signer:
            lp(signed-data)
            signatures     lp-list[ lp(uint32(algo) || lp(sig_bytes)) ]
            lp(spki_der)

        signers:
            lp-list[ signer ]
        """
        # ── signed-data ───────────────────────────────────────────────────
        digest_entry = struct.pack("<I", _SIG_RSA_PKCS1_SHA256) + _lp(content_digest)
        digests      = _lp_list(digest_entry)
        certificates = _lp_list(self._cert_der)
        attributes   = _lp(b"")              # empty list

        signed_data  = digests + certificates + attributes

        # ── signature over signed-data ────────────────────────────────────
        # The spec says: sign SHA-256(signed_data) with the private key.
        # _rsa_sign() expects a raw 32-byte SHA-256 hash and applies
        # PKCS#1 v1.5 DigestInfo wrapping internally — exactly what we need.
        sd_hash      = hashlib.sha256(signed_data).digest()
        sig_bytes    = self._rsa_sign(sd_hash)

        sig_entry    = struct.pack("<I", _SIG_RSA_PKCS1_SHA256) + _lp(sig_bytes)
        signatures   = _lp_list(sig_entry)

        # ── signer ────────────────────────────────────────────────────────
        signer = _lp(signed_data) + signatures + _lp(self._spki_der)

        # ── signers list → ID-value pair → signing block ──────────────────
        signers      = _lp_list(signer)
        return _assemble_signing_block([(_V2_SIGNATURE_ID, signers)])

    # ── zipalign ──────────────────────────────

    def _zipalign(self, apk_path: Path) -> bytes:
        out        = io.BytesIO()
        cd_entries = []

        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                if info.filename.startswith("META-INF/"):
                    continue

                raw_data      = zf.read(info.filename)
                compress_type = info.compress_type
                # Android requires these files to be STORED (uncompressed):
                # resources.arsc is memory-mapped; AndroidManifest.xml must be
                # parseable before the APK is fully loaded; .so files must be
                # STORED when extractNativeLibs=false so Android can mmap them.
                if info.filename in ("AndroidManifest.xml", "resources.arsc") \
                        or info.filename.endswith(".so"):
                    compress_type = zipfile.ZIP_STORED
                compressed    = _compress(raw_data, compress_type)
                crc           = _crc32(raw_data)
                filename_b    = info.filename.encode("utf-8")

                extra = b""
                if compress_type == zipfile.ZIP_STORED:
                    # .so files need page alignment (4096 B) for direct mmap;
                    # everything else needs 4-byte alignment.
                    align = _PAGE_ALIGN if info.filename.endswith(".so") else _ALIGN
                    extra = _padding_for_alignment(out.tell(), len(filename_b), align)

                lfh_offset = _write_lfh(
                    out, info, compress_type, crc,
                    len(compressed), len(raw_data), filename_b, extra,
                )
                out.write(compressed)
                cd_entries.append(_make_cdfh(
                    info, compress_type, crc,
                    len(compressed), len(raw_data),
                    filename_b, lfh_offset,
                ))

        _write_eocd(out, cd_entries)
        return out.getvalue()

    # ── RSA primitives ────────────────────────

    @staticmethod
    def _miller_rabin(n):
        if n < 2: return False
        if n in (2, 3, 5, 7): return True
        if n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1; d //= 2
        for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
            if a >= n: continue
            x = pow(a, d, n)
            if x in (1, n - 1): continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                return False
        return True

    @staticmethod
    def _gen_prime(bits):
        while True:
            n = int.from_bytes(os.urandom(bits // 8), "big")
            n |= (1 << (bits - 1)) | 1
            if APKSigner._miller_rabin(n):
                return n

    @staticmethod
    def _modinv(a, m):
        def _ext_gcd(a, b):
            if a == 0: return b, 0, 1
            g, x, y = _ext_gcd(b % a, a)
            return g, y - (b // a) * x, x
        _, x, _ = _ext_gcd(a % m, m)
        return x % m

    def _generate_rsa_keypair(self, bits):
        e = 65537
        while True:
            p = self._gen_prime(bits // 2)
            q = self._gen_prime(bits // 2)
            if p == q: continue
            n   = p * q
            phi = (p - 1) * (q - 1)
            if phi % e == 0: continue
            return n, e, self._modinv(e, phi), p, q

    def _rsa_sign(self, message_hash: bytes) -> bytes:
        """PKCS#1 v1.5 signature over a raw SHA-256 digest (32 bytes)."""
        digest_info = self._SHA256_DER_PREFIX + message_hash
        k           = (self._n.bit_length() + 7) // 8
        ps_len      = k - len(digest_info) - 3
        if ps_len < 8:
            raise ValueError("RSA key too small for PKCS#1 v1.5 padding")
        em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
        s  = pow(int.from_bytes(em, "big"), self._d, self._n)
        return s.to_bytes(k, "big")

    # ── X.509 / SPKI ─────────────────────────

    def _build_spki(self) -> bytes:
        """SubjectPublicKeyInfo DER — embedded standalone in the v2 signer."""
        return _der_sequence(
            _der_sequence(_der_oid(self._OID_RSA), _der_null()),
            _der_bit_string(
                _der_sequence(_der_integer(self._n), _der_integer(self._e))
            ),
        )

    def _build_x509_cert(self,
                         not_before="200101000000Z",
                         not_after="350101000000Z") -> bytes:
        def rdn(oid, val):
            return _der_set(_der_sequence(_der_oid(oid), _der_utf8string(val)))

        name = _der_sequence(
            rdn(self._OID_COUNTRY,     "US"),
            rdn(self._OID_ORG,         "Debug"),
            rdn(self._OID_COMMON_NAME, "Android Debug"),
        )
        sig_alg = _der_sequence(_der_oid(self._OID_SHA256_WITH_RSA), _der_null())
        tbs = _der_sequence(
            _der_tlv(0xA0, _der_integer(2)),
            _der_integer(1),
            sig_alg,
            name,
            _der_sequence(_der_utctime(not_before), _der_utctime(not_after)),
            name,
            self._spki_der,             # reuse already-built SPKI
        )
        return _der_sequence(
            tbs,
            sig_alg,
            _der_bit_string(self._rsa_sign(hashlib.sha256(tbs).digest())),
        )