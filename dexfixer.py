#!/usr/bin/env python3
"""
DEX Bytecode Parser and Validator

Parses and validates the instruction stream of Android Dalvik executables
(classes.dex) extracted from APK files. Detects structural malformations in
"fill-array-data-payload" pseudo-instructions (the .array-data blocks seen in
smali) — namely a declared element_width that does not conform to the DEX
specification (which only allows 1, 2, 4 or 8 bytes per element).

The actual Android file is named 'classes.dex' (or 'classesN.dex' for
secondary DEX files in multidex APKs).

Author: Cleafy Labs
Version: 1.0.0
License: MIT
"""

import struct
import zipfile
import zlib
import hashlib
import logging
import argparse
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class PseudoOpcode(IntEnum):
    """Idents of the three Dalvik pseudo-instructions (ubyte[] payload tables)."""
    PACKED_SWITCH   = 0x0100
    SPARSE_SWITCH   = 0x0200
    FILL_ARRAY_DATA = 0x0300


@dataclass
class Issue:
    severity: str   # "ERROR" | "WARNING"
    location: str
    message: str

    def __str__(self) -> str:
        color = RED if self.severity == "ERROR" else YELLOW
        return f"{color}[{self.severity}]{RESET} {self.location}: {self.message}"


@dataclass
class ParseResult:
    valid: bool = True
    issues: List[Issue] = field(default_factory=list)
    array_data_blocks_found: int = 0
    malformed_blocks: List[Dict] = field(default_factory=list)

    def error(self, location: str, msg: str) -> None:
        self.issues.append(Issue("ERROR", location, msg))
        self.valid = False

    def warning(self, location: str, msg: str) -> None:
        self.issues.append(Issue("WARNING", location, msg))

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "ERROR")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "WARNING")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class DexFixer:
    """
    Parser and validator for the Dalvik bytecode of a classes.dex file.

    Detects fill-array-data-payload blocks (the .array-data sections visible
    in a smali disassembly) whose element_width field does not conform to the
    DEX specification (valid values are 1, 2, 4 or 8 bytes). Such blocks are
    typically never referenced by an actual fill-array-data instruction, so
    ART never validates them — but they break tools that reconstruct array
    contents by following the standard bytecode semantics.

    Usage::
        with open("classes.dex", "rb") as f:
            data = f.read()
        result = DexFixer(data).parse()
        for issue in result.issues:
            print(issue)
    """

    # ── Struct formats (all little-endian) ──────────────────────────────────
    # DEX header (partial): magic(8) checksum(u32) signature(20) file_size(u32)
    #                        header_size(u32) endian_tag(u32) ...
    _MAGIC = b"dex\n"
    _HEADER_SIZE = 0x70
    _NO_INDEX = 0xFFFFFFFF

    _CLASS_DEFS_SIZE_OFF = 96
    _CLASS_DEFS_OFF_OFF  = 100
    _CLASS_DEF_SIZE      = 32          # sizeof(class_def_item)
    _METHOD_IDS_SIZE_OFF = 88
    _METHOD_IDS_OFF_OFF  = 92
    _TYPE_IDS_SIZE_OFF   = 64
    _TYPE_IDS_OFF_OFF    = 68
    _STRING_IDS_SIZE_OFF = 56
    _STRING_IDS_OFF_OFF  = 60

    _CODE_ITEM_HDR_FMT  = "<HHHHII"    # registers_size ins_size outs_size tries_size debug_info_off insns_size
    _CODE_ITEM_HDR_SIZE = 16

    VALID_ELEMENT_WIDTHS = frozenset({1, 2, 4, 8})

    # Length, in 16-bit code units, of every fixed-size instruction format.
    # Indexed by opcode byte; opcode 0x00 is special-cased (nop vs. a payload
    # marker) because its second byte selects between them — see _opcode_length().
    _OPCODE_UNITS: Dict[int, int] = {}

    @classmethod
    def _build_opcode_table(cls) -> Dict[int, int]:
        """Build the opcode → length (code units) table once, at import time."""
        table: Dict[int, int] = {}

        def set_len(opcodes, units):
            for op in opcodes:
                table[op] = units

        set_len([0x00], 1)                                    # nop (real one; see _opcode_length)
        set_len(range(0x01, 0x0A), 1)                          # move*, move-result*, move-exception
        set_len([0x02, 0x05, 0x08], 2)                         # move*/from16
        set_len([0x03, 0x06, 0x09], 3)                         # move*/16
        set_len(range(0x0A, 0x0E), 1)                          # move-result*, move-exception
        set_len([0x0E], 1)                                     # return-void
        set_len(range(0x0F, 0x12), 1)                          # return*
        set_len([0x12], 1)                                     # const/4
        set_len([0x13], 2)                                     # const/16
        set_len([0x14], 3)                                     # const
        set_len([0x15], 2)                                     # const/high16
        set_len([0x16], 2)                                     # const-wide/16
        set_len([0x17], 3)                                     # const-wide/32
        set_len([0x18], 5)                                     # const-wide
        set_len([0x19], 2)                                     # const-wide/high16
        set_len([0x1A], 2)                                     # const-string
        set_len([0x1B], 3)                                     # const-string/jumbo
        set_len([0x1C], 2)                                     # const-class
        set_len([0x1D, 0x1E], 1)                               # monitor-enter/exit
        set_len([0x1F], 2)                                     # check-cast
        set_len([0x20], 2)                                     # instance-of
        set_len([0x21], 1)                                     # array-length
        set_len([0x22], 2)                                     # new-instance
        set_len([0x23], 2)                                     # new-array
        set_len([0x24], 3)                                     # filled-new-array
        set_len([0x25], 3)                                     # filled-new-array/range
        set_len([0x26], 3)                                     # fill-array-data
        set_len([0x27], 1)                                     # throw
        set_len([0x28], 1)                                     # goto
        set_len([0x29], 2)                                     # goto/16
        set_len([0x2A], 3)                                     # goto/32
        set_len([0x2B, 0x2C], 3)                               # packed-switch, sparse-switch
        set_len(range(0x2D, 0x32), 2)                          # cmpl/cmpg/cmp-long
        set_len(range(0x32, 0x3E), 2)                          # if-* (22t) and if-*z (21t)
        set_len(range(0x3E, 0x44), 1)                          # unused
        set_len(range(0x44, 0x52), 2)                          # aget*/aput*
        set_len(range(0x52, 0x60), 2)                          # iget*/iput*
        set_len(range(0x60, 0x6E), 2)                          # sget*/sput*
        set_len(range(0x6E, 0x73), 3)                          # invoke-kind (35c)
        set_len([0x73], 1)                                     # unused
        set_len(range(0x74, 0x79), 3)                          # invoke-kind/range (3rc)
        set_len([0x79, 0x7A], 1)                                # unused
        set_len(range(0x7B, 0x90), 1)                          # unop (12x)
        set_len(range(0x90, 0xB0), 2)                          # binop (23x)
        set_len(range(0xB0, 0xD0), 1)                          # binop/2addr (12x)
        set_len(range(0xD0, 0xD8), 2)                          # binop/lit16 (22s)
        set_len(range(0xD8, 0xE3), 2)                          # binop/lit8 (22b)
        set_len(range(0xE3, 0xFA), 1)                          # unused / quickened (ODEX-only)
        set_len([0xFA, 0xFB], 4)                               # invoke-polymorphic(/range) (45cc/4rcc)
        set_len([0xFC, 0xFD], 3)                               # invoke-custom(/range) (35c/3rc)
        set_len([0xFE, 0xFF], 2)                               # const-method-handle/type (21c)

        return table

    # ── Constructor ─────────────────────────────────────────────────────────

    def __init__(self, data: bytes, main_logger: Optional[logging.Logger] = None):
        """
        Initialize the parser with the raw content of a classes.dex file.

        Args:
            data: Raw bytes of the DEX file to analyze
            main_logger: Logger

        Raises:
            ValueError: If the buffer is too small or does not start with the
                DEX magic ("dex\\n")
        """
        if len(data) < self._HEADER_SIZE or data[0:4] != self._MAGIC:
            raise ValueError("Not a valid DEX file (bad magic or truncated header)")

        self._data = data
        self._size = len(data)
        self._log = main_logger or logger

        if not DexFixer._OPCODE_UNITS:
            DexFixer._OPCODE_UNITS = self._build_opcode_table()

    # ── Public API ───────────────────────────────────────────────────────────

    def parse(self) -> ParseResult:
        """Walk every method's bytecode and validate its .array-data blocks. Returns a ParseResult."""
        self._log.info("Starting classes.dex bytecode analysis")
        result = ParseResult()

        for class_idx, method_idx, code_off in self._iter_code_items():
            location_prefix = self._describe_method(class_idx, method_idx, code_off)
            for block in self._find_array_data_blocks(code_off):
                result.array_data_blocks_found += 1
                offset, width, size = block["offset"], block["width"], block["size"]

                if width in self.VALID_ELEMENT_WIDTHS:
                    continue

                result.error(
                    f"{location_prefix}@0x{offset:08x}",
                    f"fill-array-data-payload has element_width={width}, "
                    f"which is not a valid DEX value (must be 1, 2, 4 or 8)",
                )
                result.malformed_blocks.append(
                    dict(offset=offset, width=width, size=size,
                         insns_end=block["insns_end"], location=location_prefix)
                )

        if result.valid:
            self._log.info(
                f"classes.dex analysis complete: {result.array_data_blocks_found} "
                f".array-data block(s) inspected, no malformation detected")
        else:
            self._log.warning(
                f"classes.dex analysis complete: {result.error_count} malformed "
                f".array-data block(s) out of {result.array_data_blocks_found} inspected")

        return result

    def fix(self) -> Tuple[bytes, List[str]]:
        """
        Return a corrected copy of classes.dex and a list of applied fixes.

        Correction strategy: for each malformed block, the element_width field
        is reset to 1 (byte array) and size is recomputed as the original
        size * original_width — i.e. the exact number of data bytes already
        present in the file. The total footprint of the payload (header +
        data [+ padding]) is therefore left unchanged, so no other offset in
        the file (map_list, id tables, other code_item's) needs updating.

        The header's checksum (Adler-32) and signature (SHA-1) are recomputed
        at the end, as required whenever a DEX file's content changes.
        """
        self._log.info("Applying fixes to classes.dex")
        result = self.parse()
        buf = bytearray(self._data)
        fixes: List[str] = []

        for block in result.malformed_blocks:
            offset, width, size = block["offset"], block["width"], block["size"]
            insns_end = block["insns_end"]

            data_bytes = size * width
            available = insns_end - (offset + 8)
            needed = data_bytes + (data_bytes % 2)

            if needed > available or available < 0:
                clamped = max(available - (available % 2), 0)
                self._log.warning(
                    f"{block['location']}@0x{offset:08x}: declared data ({data_bytes} bytes) "
                    f"does not fit in the code_item (available {available} bytes) -> truncating to {clamped}")
                data_bytes = clamped

            struct.pack_into("<H", buf, offset + 2, 1)             # element_width -> 1 (byte)
            struct.pack_into("<I", buf, offset + 4, data_bytes)    # size -> byte count, unchanged footprint

            fixes.append(
                f"{block['location']}@0x{offset:08x}: element_width {width} -> 1, "
                f"size {size} -> {data_bytes}")

        if fixes:
            buf = self._recompute_checksums(buf)
            self._log.info(f"classes.dex fix complete: {len(fixes)} fix(es) applied")
        else:
            self._log.info("classes.dex fix complete: no fixable issues found")

        return bytes(buf), fixes

    # ── DEX structure walking ────────────────────────────────────────────────

    def _iter_code_items(self):
        """Yield (class_idx, method_idx, code_off) for every method with a code_item."""
        class_defs_size = self._u32(self._CLASS_DEFS_SIZE_OFF)
        class_defs_off  = self._u32(self._CLASS_DEFS_OFF_OFF)

        for i in range(class_defs_size):
            base = class_defs_off + i * self._CLASS_DEF_SIZE
            if not self._has(base, self._CLASS_DEF_SIZE):
                break
            class_idx       = self._u32(base)
            class_data_off  = self._u32(base + 24)
            if class_data_off == 0:
                continue

            off = class_data_off
            static_fields_size,  off = self._read_uleb128(off)
            instance_fields_size, off = self._read_uleb128(off)
            direct_methods_size, off = self._read_uleb128(off)
            virtual_methods_size, off = self._read_uleb128(off)

            for _ in range(static_fields_size + instance_fields_size):
                _, off = self._read_uleb128(off)   # field_idx_diff
                _, off = self._read_uleb128(off)   # access_flags

            for method_count in (direct_methods_size, virtual_methods_size):
                method_idx = 0
                for _ in range(method_count):
                    diff, off = self._read_uleb128(off)
                    method_idx += diff
                    _, off = self._read_uleb128(off)          # access_flags
                    code_off, off = self._read_uleb128(off)
                    if code_off:
                        yield class_idx, method_idx, code_off

    def _find_array_data_blocks(self, code_off: int) -> List[Dict]:
        """
        Walk one code_item's instruction stream and return every
        fill-array-data-payload block found (offset/ident/width/size),
        regardless of whether it is actually referenced by a real
        fill-array-data instruction.
        """
        if not self._has(code_off, self._CODE_ITEM_HDR_SIZE):
            return []

        _, _, _, _, _, insns_size = struct.unpack_from(self._CODE_ITEM_HDR_FMT, self._data, code_off)
        insns_start = code_off + self._CODE_ITEM_HDR_SIZE
        insns_end   = insns_start + insns_size * 2

        blocks = []
        addr = 0
        while addr < insns_size:
            pos = insns_start + addr * 2
            if not self._has(pos, 2):
                break
            opcode = self._data[pos]

            if opcode == 0x00:
                units, payload = self._read_pseudo_instruction(pos)
                if payload is not None and payload["ident"] == PseudoOpcode.FILL_ARRAY_DATA:
                    blocks.append(dict(offset=pos, width=payload["width"],
                                        size=payload["size"], insns_end=insns_end))
            else:
                units = self._OPCODE_UNITS.get(opcode, 1)

            if units <= 0:
                break  # defensive: never spin on a malformed length
            addr += units

        return blocks

    def _read_pseudo_instruction(self, pos: int) -> Tuple[int, Optional[Dict]]:
        """
        Decode the code unit at `pos` (whose first byte is 0x00): either a
        real "nop" or one of the three payload pseudo-instructions. Returns
        (length_in_code_units, payload_info_or_None).
        """
        sub_opcode = self._data[pos + 1] if self._has(pos + 1, 1) else 0

        if sub_opcode == 0x00:
            return 1, None  # real nop

        if sub_opcode == 0x01 and self._has(pos, 4):   # packed-switch-payload
            size = self._u16(pos + 2)
            return 4 + size * 2, None

        if sub_opcode == 0x02 and self._has(pos, 4):   # sparse-switch-payload
            size = self._u16(pos + 2)
            return 2 + size * 4, None

        if sub_opcode == 0x03 and self._has(pos, 8):   # fill-array-data-payload
            ident  = self._u16(pos)
            width  = self._u16(pos + 2)
            size   = self._u32(pos + 4)
            data_bytes = width * size
            units = 4 + (data_bytes + (data_bytes % 2)) // 2
            return units, dict(ident=ident, width=width, size=size)

        # Unrecognised sub-opcode after a 0x00 byte: not a standard payload.
        # Stop walking this code_item rather than risk desyncing further reads.
        return 0, None

    # ── String/type resolution (best-effort, only used for log messages) ────

    def _describe_method(self, class_idx: int, method_idx: int, code_off: int) -> str:
        try:
            method_ids_off = self._u32(self._METHOD_IDS_OFF_OFF)
            m_off = method_ids_off + method_idx * 8
            m_class_idx = self._u16(m_off)
            name_idx = self._u32(m_off + 4)
            class_name = self._get_type_name(m_class_idx) or f"class#{m_class_idx}"
            method_name = self._get_string(name_idx) or f"method#{method_idx}"
            return f"{class_name}->{method_name}"
        except Exception:
            return f"class#{class_idx}->method#{method_idx}"

    def _get_type_name(self, type_idx: int) -> Optional[str]:
        type_ids_size = self._u32(self._TYPE_IDS_SIZE_OFF)
        type_ids_off  = self._u32(self._TYPE_IDS_OFF_OFF)
        if type_idx == self._NO_INDEX or type_idx >= type_ids_size:
            return None
        return self._get_string(self._u32(type_ids_off + type_idx * 4))

    def _get_string(self, string_idx: int) -> Optional[str]:
        string_ids_size = self._u32(self._STRING_IDS_SIZE_OFF)
        string_ids_off  = self._u32(self._STRING_IDS_OFF_OFF)
        if string_idx == self._NO_INDEX or string_idx >= string_ids_size:
            return None
        data_off = self._u32(string_ids_off + string_idx * 4)
        _, cur = self._read_uleb128(data_off)
        end = cur
        while end < self._size and self._data[end] != 0:
            end += 1
        return self._data[cur:end].decode("utf-8", errors="replace")

    # ── Low-level helpers ────────────────────────────────────────────────────

    def _read_uleb128(self, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        start = offset
        while True:
            if offset >= self._size:
                raise ValueError(f"Truncated ULEB128 at 0x{start:08x}")
            byte = self._data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset

    def _u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self._data, offset)[0]

    def _u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self._data, offset)[0]

    def _has(self, offset: int, length: int) -> bool:
        return 0 <= offset and offset + length <= self._size

    def _recompute_checksums(self, buf: bytearray) -> bytearray:
        """Recompute the DEX header's SHA-1 signature and Adler-32 checksum in place."""
        signature = hashlib.sha1(bytes(buf[32:])).digest()
        buf[12:32] = signature
        checksum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", buf, 8, checksum)
        return buf


# ---------------------------------------------------------------------------
# Helpers: load classes.dex from a file or APK
# ---------------------------------------------------------------------------

def load_from_apk(apk_path: str, dex_name: str = "classes.dex") -> Optional[bytes]:
    """Extract a DEX file from an APK (ZIP) archive. Returns None if not found."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if dex_name not in zf.namelist():
                logger.error(f"{dex_name} not found inside {apk_path}")
                return None
            return zf.read(dex_name)
    except zipfile.BadZipFile as e:
        logger.error(f"Cannot open {apk_path} as a ZIP/APK: {e}")
        return None


def load_dex(path: str, dex_name: str = "classes.dex") -> Optional[bytes]:
    """Load DEX data from a standalone .dex file or an .apk."""
    p = Path(path)
    if not p.exists():
        logger.error(f"File not found: {path}")
        return None
    if p.suffix.lower() == ".apk":
        return load_from_apk(path, dex_name)
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="DexFixer — parse, validate and fix malformed .array-data "
                    "blocks in a classes.dex (standalone or extracted from an APK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python dexfixer.py classes.dex
    python dexfixer.py app.apk
    python dexfixer.py classes.dex --fix --output classes-fixed.dex
        """,
    )
    ap.add_argument("path", help="Path to classes.dex or an APK file")
    ap.add_argument("--dex-name", default="classes.dex", metavar="NAME",
                     help="Name of the DEX entry to read when --path is an APK (default: classes.dex)")
    ap.add_argument(
        "--fix", action="store_true",
        help="Correct detected malformations",
    )
    ap.add_argument(
        "--output", "-o", default=None, metavar="DEX_FILE",
        help="Write the fixed classes.dex to this path (requires --fix)",
    )
    ap.add_argument(
        "--log-level", "-l",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: WARNING)",
    )
    args = ap.parse_args()

    if args.output and not args.fix:
        ap.error("--output requires --fix")
    if args.fix and not args.output:
        ap.error("--fix requires --output")

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )

    data = load_dex(args.path, args.dex_name)
    if data is None:
        raise SystemExit(1)

    try:
        parser = DexFixer(data)
    except ValueError as e:
        logger.error(str(e))
        raise SystemExit(1)

    result = parser.parse()

    print(f"\n.array-data blocks inspected: {result.array_data_blocks_found}")
    for issue in result.issues:
        print(f"  {issue}")

    if result.valid:
        print(f"\n{GREEN}No malformation detected.{RESET}")
    else:
        print(f"\n{RED}{result.error_count} malformed block(s) detected.{RESET}")

    if args.fix:
        fixed_data, fixes = parser.fix()
        if fixes:
            with open(args.output, "wb") as f:
                f.write(fixed_data)
            print(f"\n{GREEN}Fixed classes.dex written to: {args.output}{RESET}")
            print(f"{len(fixes)} fix(es) applied.")
        else:
            print("\nNo fixable issues found; no output file written.")


if __name__ == "__main__":
    main()
