#!/usr/bin/env python3
"""
resources.arsc Parser and Validator

Parses and validates Android compiled resource tables (resources.arsc) extracted
from APK files. Detects structural malformations including bad chunk headers,
invalid string pool offsets, corrupt package/type/entry data, and malformed values.

The actual Android file is named 'resources.arsc'.

Author: Cleafy Labs
Version: 1.0.0
License: MIT
"""

import struct
import zipfile
import io
import os
import shutil
import tempfile
import logging
import argparse
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from apksigner import APKSigner as _APKSigner
    _APKSIGNER_AVAILABLE = True
except ImportError:
    _APKSIGNER_AVAILABLE = False

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chunk type constants
# ---------------------------------------------------------------------------

class ChunkType(IntEnum):
    STRING_POOL     = 0x0001
    TABLE           = 0x0002
    TABLE_PACKAGE   = 0x0200
    TABLE_TYPE      = 0x0201
    TABLE_TYPE_SPEC = 0x0202
    TABLE_LIBRARY   = 0x0203


class StringPoolFlags(IntEnum):
    SORTED_FLAG = 1 << 0
    UTF8_FLAG   = 1 << 8


class EntryFlags(IntEnum):
    FLAG_COMPLEX = 0x0001
    FLAG_PUBLIC  = 0x0002
    FLAG_WEAK    = 0x0004


# ---------------------------------------------------------------------------
# Issue tracking
# ---------------------------------------------------------------------------

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
    package_count_declared: int = 0
    packages: List[Dict] = field(default_factory=list)

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

class ArscFixer:
    """
    Parser and validator for Android's compiled resource table (resources.arsc).

    Detects: bad chunk types/sizes, out-of-bounds offsets, corrupt string pools,
    mismatched typeSpec/type declarations, and malformed entry/value data.

    Usage::
        with open("resources.arsc", "rb") as f:
            data = f.read()
        result = ArscFixer(data).parse()
        for issue in result.issues:
            print(issue)
    """

    # ── Struct formats (all little-endian) ──────────────────────────────────
    # ResChunk_header: type(u16) headerSize(u16) size(u32)
    _CH_FMT  = "<HHI"
    _CH_SIZE = struct.calcsize(_CH_FMT)   # 8

    # ResTable_header adds: packageCount(u32)
    _TABLE_HDR_SIZE = _CH_SIZE + 4        # 12

    # ResStringPool_header: chunk_header + stringCount styleCount flags stringsStart stylesStart
    _SP_FMT  = "<HHI IIIII"
    _SP_SIZE = struct.calcsize(_SP_FMT)   # 28

    # ResTable_package: chunk_header + id(u32) + name[128 char16=256B] + 5×u32
    #   (typeStrings, lastPublicType, keyStrings, lastPublicKey, typeIdOffset)
    _PKG_FMT  = "<HHI I 256s IIIII"
    _PKG_SIZE = struct.calcsize(_PKG_FMT) # 288

    # ResTable_typeSpec: chunk_header + id(u8) res0(u8) res1(u16) entryCount(u32)
    _TS_FMT  = "<HHI BBHI"
    _TS_SIZE = struct.calcsize(_TS_FMT)   # 16

    # ResTable_type header (excluding variable-length ResTable_config):
    #   chunk_header + id(u8) flags(u8) reserved(u16) entryCount(u32) entriesStart(u32)
    _TT_FMT  = "<HHI BBHII"
    _TT_MIN  = struct.calcsize(_TT_FMT)   # 20

    # ResTable_entry: size(u16) flags(u16) key(u32)
    _ENTRY_FMT  = "<HHI"
    _ENTRY_SIZE = struct.calcsize(_ENTRY_FMT)   # 8

    # Res_value: size(u16) res0(u8) dataType(u8) data(u32)
    _VAL_FMT  = "<HBBI"
    _VAL_SIZE = struct.calcsize(_VAL_FMT)   # 8

    # ResTable_map_entry extras after ResTable_entry: parent(u32) count(u32)
    _MAP_EXTRA_FMT  = "<II"
    _MAP_EXTRA_SIZE = struct.calcsize(_MAP_EXTRA_FMT)   # 8

    # ResTable_map: name(u32) + Res_value(8)
    _MAP_SIZE = 4 + _VAL_SIZE             # 12

    _CONFIG_MIN_SIZE = 28   # smallest ResTable_config (pre-API 21 devices)

    # ── Constructor ─────────────────────────────────────────────────────────

    def __init__(self, data: bytes, ext_logger: Optional[logging.Logger] = None):
        self._data = data
        self._size = len(data)
        self._log  = ext_logger or logger

    # ── Public API ───────────────────────────────────────────────────────────

    def parse(self) -> ParseResult:
        """Parse and validate the resource table. Returns a ParseResult with all detected issues."""
        self._log.info("Starting resources.arsc analysis")
        result = ParseResult()

        if self._size < self._TABLE_HDR_SIZE:
            result.error("file", f"File too small ({self._size} bytes) to be a valid resources.arsc")
            return result

        ctype, header_size, chunk_size = struct.unpack_from(self._CH_FMT, self._data, 0)

        if ctype != ChunkType.TABLE:
            result.error("0x00000000",
                f"Expected RES_TABLE_TYPE (0x{ChunkType.TABLE:04x}), got 0x{ctype:04x}")
            return result

        if header_size < self._TABLE_HDR_SIZE:
            result.error("TableHeader@0x00000000",
                f"headerSize={header_size} < minimum {self._TABLE_HDR_SIZE}")
            return result

        if chunk_size != self._size:
            result.warning("TableHeader@0x00000000",
                f"Root chunk size {chunk_size} != file size {self._size}")

        pkg_count_declared = struct.unpack_from("<I", self._data, 8)[0]
        result.package_count_declared = pkg_count_declared

        offset = header_size
        pkg_count_found = 0
        sp_found        = False

        while offset < self._size:
            if not self._has(offset, self._CH_SIZE):
                result.error(f"0x{offset:08x}", "Not enough bytes for a chunk header (truncated file?)")
                break

            ctype, cheader_size, csize = struct.unpack_from(self._CH_FMT, self._data, offset)

            if csize == 0:
                result.error(f"0x{offset:08x}", "Chunk size is 0 — would cause infinite loop")
                break

            if not self._check_chunk(offset, cheader_size, csize, self._size, result):
                break

            if ctype == ChunkType.STRING_POOL:
                if sp_found:
                    result.warning(f"StringPool@0x{offset:08x}",
                        "Multiple top-level StringPool chunks (only the first is expected)")
                self._parse_string_pool(offset, csize, result)
                sp_found = True

            elif ctype == ChunkType.TABLE_PACKAGE:
                pkg = self._parse_package(offset, csize, result)
                if pkg is not None:
                    result.packages.append(pkg)
                pkg_count_found += 1

            else:
                result.warning(f"0x{offset:08x}",
                    f"Unexpected top-level chunk type 0x{ctype:04x}")

            offset += csize

        if not sp_found:
            result.warning("file", "No top-level StringPool chunk found (global string pool missing)")

        if pkg_count_found != pkg_count_declared:
            result.warning("TableHeader@0x00000000",
                f"Declared packageCount={pkg_count_declared} but found {pkg_count_found} package(s)")

        if result.valid and not result.issues:
            self._log.info("resources.arsc analysis complete: no issues detected")
        elif result.valid:
            self._log.warning(
                f"resources.arsc analysis complete: {result.warning_count} warning(s) detected")
        else:
            self._log.warning(
                f"resources.arsc analysis complete: {result.error_count} error(s), "
                f"{result.warning_count} warning(s) detected")

        return result

    # ── String pool ──────────────────────────────────────────────────────────

    def _parse_string_pool(self, base: int, chunk_size: int,
                            result: ParseResult) -> Optional[List[str]]:
        loc = f"StringPool@0x{base:08x}"

        if chunk_size < self._SP_SIZE:
            result.error(loc, f"Chunk too small for StringPool header ({chunk_size} B < {self._SP_SIZE} B)")
            return None

        (_, header_size, _,
         string_count, style_count, flags,
         strings_start, styles_start) = struct.unpack_from(self._SP_FMT, self._data, base)

        is_utf8       = bool(flags & StringPoolFlags.UTF8_FLAG)
        chunk_end     = base + chunk_size
        strings_base  = base + strings_start

        # Offset array bounds
        offsets_start = base + header_size
        offsets_end   = offsets_start + string_count * 4
        if offsets_end > chunk_end:
            result.error(loc,
                f"String offset array ({string_count}×4 B) exceeds chunk boundary "
                f"(need 0x{offsets_end:08x}, chunk ends 0x{chunk_end:08x})")
            return None

        if style_count > 0:
            style_arr_end = offsets_end + style_count * 4
            if style_arr_end > chunk_end:
                result.error(loc,
                    f"Style offset array ({style_count}×4 B) exceeds chunk boundary")

        if string_count > 0 and strings_start >= chunk_size:
            result.error(loc,
                f"stringsStart=0x{strings_start:08x} >= chunk size {chunk_size} "
                f"— string data unreachable")
            return None

        if styles_start != 0 and styles_start >= chunk_size:
            result.error(loc, f"stylesStart=0x{styles_start:08x} >= chunk size {chunk_size}")

        strings: List[str] = []
        for i in range(string_count):
            rel_off  = struct.unpack_from("<I", self._data, offsets_start + i * 4)[0]
            abs_off  = strings_base + rel_off
            try:
                s = self._read_string(abs_off, is_utf8, chunk_end)
                strings.append(s)
            except Exception as ex:
                result.warning(loc, f"String[{i}] at 0x{abs_off:08x}: {ex}")
                strings.append("")

        return strings

    def _read_string(self, offset: int, is_utf8: bool, limit: int) -> str:
        if offset + 2 > limit:
            raise ValueError("Offset past chunk boundary")

        if is_utf8:
            # Two length prefixes: char count, then byte count (each 1 or 2 bytes)
            _, skip = self._utf8_len(offset)
            offset += skip
            byte_len, skip = self._utf8_len(offset)
            offset += skip
            if offset + byte_len > limit:
                raise ValueError(f"UTF-8 string data ({byte_len} B) exceeds chunk boundary")
            return self._data[offset: offset + byte_len].decode("utf-8", errors="replace")
        else:
            # One length prefix (1 or 2 uint16), then char data in UTF-16LE
            char_len, skip = self._utf16_len(offset)
            offset += skip
            byte_len = char_len * 2
            if offset + byte_len + 2 > limit:
                raise ValueError(f"UTF-16LE string data ({byte_len} B) exceeds chunk boundary")
            return self._data[offset: offset + byte_len].decode("utf-16-le", errors="replace")

    def _utf8_len(self, offset: int) -> Tuple[int, int]:
        b = self._data[offset]
        return (((b & 0x7F) << 8) | self._data[offset + 1], 2) if (b & 0x80) else (b, 1)

    def _utf16_len(self, offset: int) -> Tuple[int, int]:
        v = struct.unpack_from("<H", self._data, offset)[0]
        if v & 0x8000:
            hi = struct.unpack_from("<H", self._data, offset + 2)[0]
            return ((v & 0x7FFF) << 16) | hi, 4
        return v, 2

    # ── Package ──────────────────────────────────────────────────────────────

    def _parse_package(self, base: int, chunk_size: int,
                        result: ParseResult) -> Optional[Dict]:
        loc = f"Package@0x{base:08x}"

        if chunk_size < self._PKG_SIZE:
            result.error(loc,
                f"Chunk too small for Package header ({chunk_size} B < {self._PKG_SIZE} B)")
            return None

        (_, header_size, _,
         pkg_id, name_raw,
         type_strings_off, last_public_type,
         key_strings_off,  last_public_key,
         type_id_offset) = struct.unpack_from(self._PKG_FMT, self._data, base)

        # Decode null-terminated UTF-16LE package name from 256-byte buffer
        try:
            end = 0
            while end < len(name_raw) - 1:
                if name_raw[end] == 0 and name_raw[end + 1] == 0:
                    break
                end += 2
            pkg_name = name_raw[:end].decode("utf-16-le", errors="replace")
        except Exception:
            pkg_name = "<decode error>"
            result.warning(loc, "Could not decode package name field")

        if pkg_id == 0:
            result.error(loc, "Package ID is 0 (invalid; valid range is 0x01–0xFF)")
        elif pkg_id not in (0x01, 0x7F):
            result.warning(loc,
                f"Unusual package ID 0x{pkg_id:02x} "
                "(expected 0x7F for app resources, 0x01 for android framework)")

        for attr, off in (("typeStrings", type_strings_off), ("keyStrings", key_strings_off)):
            if off == 0:
                result.warning(loc, f"{attr} offset is 0 (missing string pool?)")
            elif off >= chunk_size:
                result.error(loc, f"{attr} offset 0x{off:08x} >= chunk size {chunk_size}")

        # Parse string pools embedded in the package chunk
        type_strings: List[str] = []
        key_strings:  List[str] = []

        if type_strings_off and type_strings_off < chunk_size:
            sp = self._parse_string_pool(base + type_strings_off,
                                          chunk_size - type_strings_off, result)
            if sp is not None:
                type_strings = sp

        if key_strings_off and key_strings_off < chunk_size:
            sp = self._parse_string_pool(base + key_strings_off,
                                          chunk_size - key_strings_off, result)
            if sp is not None:
                key_strings = sp

        # Walk sub-chunks (typeSpec + type tables)
        offset    = base + header_size
        pkg_end   = base + chunk_size
        type_specs: Dict[int, int] = {}   # type_id → entry_count
        types: List[Dict] = []

        while offset < pkg_end:
            if not self._has(offset, self._CH_SIZE):
                if offset < pkg_end:
                    result.warning(loc, f"Trailing {pkg_end - offset} byte(s) after last sub-chunk")
                break

            ctype, cheader_sz, csize = struct.unpack_from(self._CH_FMT, self._data, offset)

            if csize == 0:
                result.error(f"subchunk@0x{offset:08x}", "Sub-chunk size is 0")
                break

            if offset + csize > pkg_end:
                result.error(f"subchunk@0x{offset:08x}",
                    f"Sub-chunk extends {offset + csize - pkg_end} B beyond package boundary")
                csize = pkg_end - offset   # clamp and continue

            if ctype == ChunkType.STRING_POOL:
                pass   # already consumed above via typeStrings/keyStrings offsets

            elif ctype == ChunkType.TABLE_TYPE_SPEC:
                info = self._parse_type_spec(offset, csize, result)
                if info is not None:
                    tid, cnt = info
                    if tid in type_specs:
                        result.warning(f"TypeSpec@0x{offset:08x}",
                            f"Duplicate TypeSpec for type id={tid}")
                    type_specs[tid] = cnt

            elif ctype == ChunkType.TABLE_TYPE:
                tinfo = self._parse_type(offset, csize, result, type_strings, key_strings)
                if tinfo is not None:
                    types.append(tinfo)

            elif ctype == ChunkType.TABLE_LIBRARY:
                pass   # shared library references — structural check only

            else:
                result.warning(f"subchunk@0x{offset:08x}",
                    f"Unknown sub-chunk type 0x{ctype:04x} inside package")

            offset += csize

        # Every type chunk must have a matching typeSpec
        for t in types:
            if t["id"] not in type_specs:
                result.warning(loc,
                    f"ResTable_type id={t['id']} ('{t['name']}') "
                    f"has no corresponding ResTable_typeSpec")

        return {
            "id": pkg_id,
            "name": pkg_name,
            "type_strings": type_strings,
            "key_strings": key_strings,
            "type_specs": type_specs,
            "types": types,
        }

    # ── TypeSpec ─────────────────────────────────────────────────────────────

    def _parse_type_spec(self, base: int, chunk_size: int,
                          result: ParseResult) -> Optional[Tuple[int, int]]:
        loc = f"TypeSpec@0x{base:08x}"

        if chunk_size < self._TS_SIZE:
            result.error(loc, f"Chunk too small ({chunk_size} B < {self._TS_SIZE} B)")
            return None

        (_, header_size, _,
         type_id, res0, res1, entry_count) = struct.unpack_from(self._TS_FMT, self._data, base)

        if type_id == 0:
            result.error(loc, "Type ID is 0 (type IDs are 1-based)")

        if res0 != 0:
            result.warning(loc, f"res0=0x{res0:02x} should be 0x00")

        needed = header_size + entry_count * 4
        if chunk_size < needed:
            result.error(loc,
                f"Chunk size {chunk_size} < header({header_size}) "
                f"+ flags array({entry_count}×4={entry_count*4}) = {needed}")

        return type_id, entry_count

    # ── Type ─────────────────────────────────────────────────────────────────

    def _parse_type(self, base: int, chunk_size: int, result: ParseResult,
                    type_strings: List[str], key_strings: List[str]) -> Optional[Dict]:
        loc = f"Type@0x{base:08x}"

        if chunk_size < self._TT_MIN + self._CONFIG_MIN_SIZE:
            result.error(loc, f"Chunk too small for Type header+config ({chunk_size} B)")
            return None

        (_, header_size, _,
         type_id, tflags, reserved,
         entry_count, entries_start) = struct.unpack_from(self._TT_FMT, self._data, base)

        if type_id == 0:
            result.error(loc, "Type ID is 0 (type IDs are 1-based)")

        if reserved != 0:
            result.warning(loc, f"reserved field = 0x{reserved:04x} (should be 0x0000)")

        # ResTable_config.size is the first uint32 right after the fixed header
        config_off = base + self._TT_MIN
        if not self._has(config_off, 4):
            result.error(loc, "Cannot read ResTable_config.size (truncated)")
            return None

        config_size = struct.unpack_from("<I", self._data, config_off)[0]
        if config_size < self._CONFIG_MIN_SIZE:
            result.warning(loc,
                f"ResTable_config.size={config_size} < minimum {self._CONFIG_MIN_SIZE}")

        if config_size > chunk_size:
            result.error(loc,
                f"ResTable_config.size={config_size} exceeds chunk size {chunk_size}")
            return None

        expected_header = self._TT_MIN + config_size
        if header_size < expected_header:
            result.warning(loc,
                f"headerSize={header_size} < TT_MIN({self._TT_MIN}) + "
                f"config_size({config_size}) = {expected_header}")

        # Entry offset table: entry_count × uint32
        offsets_start = base + header_size
        offsets_end   = offsets_start + entry_count * 4
        chunk_end     = base + chunk_size

        if offsets_end > chunk_end:
            result.error(loc,
                f"Entry offset table ({entry_count}×4 B) extends beyond chunk boundary "
                f"(need 0x{offsets_end:08x}, chunk ends 0x{chunk_end:08x})")
            return None

        entries_base = base + entries_start
        if entries_base > chunk_end:
            result.error(loc,
                f"entriesStart=0x{entries_start:08x} places entry data past chunk end 0x{chunk_end:08x}")
            return None

        type_name = (type_strings[type_id - 1]
                     if type_strings and type_id - 1 < len(type_strings)
                     else f"<type#{type_id}>")

        err_count = 0
        for i in range(entry_count):
            raw_off = struct.unpack_from("<I", self._data, offsets_start + i * 4)[0]
            if raw_off == 0xFFFFFFFF:
                continue   # NO_ENTRY sentinel — valid, means this config has no value for entry i

            entry_abs = entries_base + raw_off

            if not self._has(entry_abs, self._ENTRY_SIZE) or entry_abs + self._ENTRY_SIZE > chunk_end:
                result.error(loc,
                    f"Entry[{i}] at 0x{entry_abs:08x} truncated "
                    f"(chunk end=0x{chunk_end:08x})")
                err_count += 1
                continue

            entry_size, entry_flags, key_idx = struct.unpack_from(
                self._ENTRY_FMT, self._data, entry_abs)

            if entry_size < self._ENTRY_SIZE:
                result.error(loc,
                    f"Entry[{i}] size={entry_size} < minimum {self._ENTRY_SIZE}")
                err_count += 1
                continue

            if key_strings and key_idx >= len(key_strings):
                result.warning(loc,
                    f"Entry[{i}] key index {key_idx} out of range "
                    f"(key pool has {len(key_strings)} entries)")

            if entry_flags & EntryFlags.FLAG_COMPLEX:
                # ResTable_map_entry appends parent(u32) + count(u32) after the base entry
                if entry_size < self._ENTRY_SIZE + self._MAP_EXTRA_SIZE:
                    result.error(loc,
                        f"Entry[{i}] complex map entry size={entry_size} too small "
                        f"(expected ≥{self._ENTRY_SIZE + self._MAP_EXTRA_SIZE})")
                    err_count += 1
                    continue

                _, map_count = struct.unpack_from(
                    self._MAP_EXTRA_FMT, self._data, entry_abs + self._ENTRY_SIZE)

                maps_end = entry_abs + entry_size + map_count * self._MAP_SIZE
                if maps_end > chunk_end:
                    result.warning(loc,
                        f"Entry[{i}] map data ({map_count} items, "
                        f"ends 0x{maps_end:08x}) exceeds chunk boundary 0x{chunk_end:08x}")
                else:
                    # Validate each ResTable_map value's size/res0 fields
                    for m in range(map_count):
                        val_off = entry_abs + entry_size + m * self._MAP_SIZE + 4
                        val_size, val_res0, _, _ = struct.unpack_from(
                            self._VAL_FMT, self._data, val_off)
                        if val_size != self._VAL_SIZE:
                            result.warning(loc,
                                f"Entry[{i}].map[{m}] Res_value.size={val_size} "
                                f"(expected {self._VAL_SIZE})")
                        if val_res0 != 0:
                            result.warning(loc,
                                f"Entry[{i}].map[{m}] Res_value.res0=0x{val_res0:02x} "
                                f"(should be 0x00)")
            else:
                # Simple entry: Res_value immediately follows the entry header
                val_abs = entry_abs + entry_size
                if val_abs + self._VAL_SIZE > chunk_end:
                    result.error(loc,
                        f"Entry[{i}] Res_value at 0x{val_abs:08x} extends past "
                        f"chunk end 0x{chunk_end:08x}")
                    err_count += 1
                    continue

                val_size, val_res0, data_type, _ = struct.unpack_from(
                    self._VAL_FMT, self._data, val_abs)

                if val_size != self._VAL_SIZE:
                    result.warning(loc,
                        f"Entry[{i}] Res_value.size={val_size} (expected {self._VAL_SIZE})")
                if val_res0 != 0:
                    result.warning(loc,
                        f"Entry[{i}] Res_value.res0=0x{val_res0:02x} (should be 0x00)")

        if err_count:
            result.warning(loc,
                f"{err_count}/{entry_count} entries had structural errors in type '{type_name}'")

        return {"id": type_id, "name": type_name, "entry_count": entry_count}

    # ── Fix ──────────────────────────────────────────────────────────────────

    def fix(self) -> Tuple[bytes, List[str]]:
        """
        Return a corrected copy of the resource table and a list of applied fixes.

        Correction strategies (in priority order):
        1. Entry offset table reconstruction via scan-forward: when scanning sequentially
           from entriesStart finds exactly entry_count valid entries, the reconstructed
           offsets replace the entire (likely corrupted) offset table.
        2. Upper-16-bit mask fallback: for any remaining out-of-bounds offset whose lower
           16 bits land on a valid entry (size ≥ 8), mask away the high bits.
        3. NO_ENTRY sentinel: offsets that are still unresolvable, or entries with size=0
           after correction, are replaced with 0xFFFFFFFF.
        4. Res_value patch: size field != 8 is corrected to 8; non-zero res0 is zeroed.
        5. Root chunk size: if the root chunk's size field doesn't match the file length,
           it is patched to match.
        """
        self._log.info("Applying fixes to resources.arsc")
        buf = bytearray(self._data)
        fixes: List[str] = []

        if self._size < self._TABLE_HDR_SIZE:
            return bytes(buf), fixes

        ctype, header_size, chunk_size = struct.unpack_from(self._CH_FMT, buf, 0)
        if ctype != ChunkType.TABLE:
            return bytes(buf), fixes

        if chunk_size != self._size:
            struct.pack_into("<I", buf, 4, self._size)
            fixes.append(f"TableHeader: root chunk size {chunk_size} → {self._size}")

        offset = header_size
        while offset < self._size:
            if offset + self._CH_SIZE > self._size:
                break
            ctype, cheader_size, csize = struct.unpack_from(self._CH_FMT, buf, offset)
            if csize == 0:
                break
            csize = min(csize, self._size - offset)
            if ctype == ChunkType.TABLE_PACKAGE:
                self._fix_package(buf, fixes, offset, csize)
            offset += csize

        if fixes:
            self._log.info(f"resources.arsc fix complete: {len(fixes)} fix(es) applied")
        else:
            self._log.info("resources.arsc fix complete: no fixable issues found")

        return bytes(buf), fixes

    def _fix_package(self, buf: bytearray, fixes: List[str], base: int, chunk_size: int) -> None:
        if chunk_size < self._PKG_SIZE:
            return
        _, header_size, _ = struct.unpack_from(self._CH_FMT, buf, base)
        offset  = base + header_size
        pkg_end = base + chunk_size
        while offset < pkg_end:
            if offset + self._CH_SIZE > pkg_end:
                break
            ctype, _, csize = struct.unpack_from(self._CH_FMT, buf, offset)
            if csize == 0:
                break
            csize = min(csize, pkg_end - offset)
            if ctype == ChunkType.TABLE_TYPE:
                self._fix_type(buf, fixes, offset, csize)
            offset += csize

    def _fix_type(self, buf: bytearray, fixes: List[str], base: int, chunk_size: int) -> None:
        loc = f"Type@0x{base:08x}"
        if chunk_size < self._TT_MIN + self._CONFIG_MIN_SIZE:
            return

        (_, header_size, _,
         type_id, _, _,
         entry_count, entries_start) = struct.unpack_from(self._TT_FMT, buf, base)

        offsets_start = base + header_size
        offsets_end   = offsets_start + entry_count * 4
        chunk_end     = base + chunk_size
        entries_base  = base + entries_start

        if offsets_end > chunk_end or entries_base > chunk_end:
            return

        # Detect whether the offset table needs fixing
        needs_fix = False
        for i in range(entry_count):
            raw = struct.unpack_from("<I", buf, offsets_start + i * 4)[0]
            if raw == 0xFFFFFFFF:
                continue
            entry_abs = entries_base + raw
            if entry_abs + self._ENTRY_SIZE > chunk_end:
                needs_fix = True
                break
            if struct.unpack_from("<H", buf, entry_abs)[0] == 0:
                needs_fix = True
                break

        if needs_fix:
            # ── Strategy 1: scan-forward reconstruction ───────────────
            scanned = self._scan_entries(buf, entries_base, chunk_end)

            if len(scanned) == entry_count:
                changed = 0
                for i, new_off in enumerate(scanned):
                    pos = offsets_start + i * 4
                    if struct.unpack_from("<I", buf, pos)[0] != new_off:
                        struct.pack_into("<I", buf, pos, new_off)
                        changed += 1
                if changed:
                    fixes.append(
                        f"{loc}: reconstructed {changed}/{entry_count} "
                        f"entry offsets via scan-forward"
                    )
            else:
                # ── Strategy 2: per-entry mask / sentinel fallback ────
                for i in range(entry_count):
                    pos     = offsets_start + i * 4
                    raw_off = struct.unpack_from("<I", buf, pos)[0]
                    if raw_off == 0xFFFFFFFF:
                        continue

                    entry_abs = entries_base + raw_off
                    if entry_abs + self._ENTRY_SIZE <= chunk_end:
                        if struct.unpack_from("<H", buf, entry_abs)[0] >= self._ENTRY_SIZE:
                            continue   # already valid

                    # Try masking upper 16 bits
                    masked    = raw_off & 0x0000FFFF
                    masked_abs = entries_base + masked
                    if masked_abs + self._ENTRY_SIZE <= chunk_end:
                        sz = struct.unpack_from("<H", buf, masked_abs)[0]
                        if sz >= self._ENTRY_SIZE:
                            struct.pack_into("<I", buf, pos, masked)
                            fixes.append(
                                f"{loc}: Entry[{i}] offset 0x{raw_off:08x} → "
                                f"0x{masked:04x} (upper-16 mask)"
                            )
                            continue

                    # Strategy 3: mark as NO_ENTRY
                    struct.pack_into("<I", buf, pos, 0xFFFFFFFF)
                    fixes.append(f"{loc}: Entry[{i}] 0x{raw_off:08x} unrecoverable → NO_ENTRY")

                # size=0 entries remaining after above passes
                for i in range(entry_count):
                    pos     = offsets_start + i * 4
                    raw_off = struct.unpack_from("<I", buf, pos)[0]
                    if raw_off == 0xFFFFFFFF:
                        continue
                    entry_abs = entries_base + raw_off
                    if entry_abs + 2 <= chunk_end:
                        if struct.unpack_from("<H", buf, entry_abs)[0] == 0:
                            struct.pack_into("<I", buf, pos, 0xFFFFFFFF)
                            fixes.append(f"{loc}: Entry[{i}] size=0 → NO_ENTRY")

        # ── Strategy 4: Res_value field patches ───────────────────────
        for i in range(entry_count):
            raw_off = struct.unpack_from("<I", buf, offsets_start + i * 4)[0]
            if raw_off == 0xFFFFFFFF:
                continue
            entry_abs = entries_base + raw_off
            if entry_abs + self._ENTRY_SIZE > chunk_end:
                continue
            entry_size, entry_flags, _ = struct.unpack_from(self._ENTRY_FMT, buf, entry_abs)
            if entry_size < self._ENTRY_SIZE or (entry_flags & EntryFlags.FLAG_COMPLEX):
                continue
            val_abs = entry_abs + entry_size
            if val_abs + self._VAL_SIZE > chunk_end:
                continue
            val_size, val_res0, _, _ = struct.unpack_from(self._VAL_FMT, buf, val_abs)
            if val_size != self._VAL_SIZE:
                struct.pack_into("<H", buf, val_abs, self._VAL_SIZE)
                fixes.append(f"{loc}: Entry[{i}] Res_value.size {val_size} → {self._VAL_SIZE}")
            if val_res0 != 0:
                struct.pack_into("<B", buf, val_abs + 2, 0)
                fixes.append(f"{loc}: Entry[{i}] Res_value.res0 0x{val_res0:02x} → 0x00")

    def _scan_entries(self, data, entries_base: int, chunk_end: int) -> List[int]:
        """
        Walk entries sequentially from entries_base using each entry's own size field.
        Returns offsets (relative to entries_base) of every valid entry found.

        Stops at the first entry whose size field is out of range or whose data would
        exceed the chunk boundary — so a partial result is possible when entries are
        sparse or the data is only partially recoverable.
        """
        offsets: List[int] = []
        pos = entries_base
        while pos < chunk_end:
            if pos + self._ENTRY_SIZE > chunk_end:
                break
            entry_size, entry_flags, _ = struct.unpack_from(self._ENTRY_FMT, data, pos)
            if entry_size < self._ENTRY_SIZE:
                break
            if entry_flags & EntryFlags.FLAG_COMPLEX:
                if entry_size < self._ENTRY_SIZE + self._MAP_EXTRA_SIZE:
                    break
                _, map_count = struct.unpack_from(self._MAP_EXTRA_FMT, data,
                                                   pos + self._ENTRY_SIZE)
                total = entry_size + map_count * self._MAP_SIZE
            else:
                total = entry_size + self._VAL_SIZE
            if pos + total > chunk_end:
                break
            offsets.append(pos - entries_base)
            pos += total
        return offsets

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _has(self, offset: int, length: int) -> bool:
        return offset + length <= self._size

    def _check_chunk(self, offset: int, header_size: int, chunk_size: int,
                      limit: int, result: ParseResult) -> bool:
        loc = f"chunk@0x{offset:08x}"
        if header_size < self._CH_SIZE:
            result.error(loc, f"headerSize={header_size} < minimum {self._CH_SIZE}")
            return False
        if header_size > chunk_size:
            result.error(loc, f"headerSize={header_size} > chunkSize={chunk_size}")
            return False
        if offset + chunk_size > limit:
            result.error(loc,
                f"Chunk extends {offset + chunk_size - limit} byte(s) past file end")
            return False
        return True


# ---------------------------------------------------------------------------
# Helpers: load resources.arsc from a file or APK
# ---------------------------------------------------------------------------

def load_from_apk(apk_path: str) -> Optional[bytes]:
    """Extract resources.arsc from an APK (ZIP) file. Returns None if not found."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "resources.arsc" not in zf.namelist():
                logger.error(f"resources.arsc not found inside {apk_path}")
                return None
            return zf.read("resources.arsc")
    except zipfile.BadZipFile as e:
        logger.error(f"Cannot open {apk_path} as a ZIP/APK: {e}")
        return None


def load_arsc(path: str) -> Optional[bytes]:
    """Load resources.arsc data from a standalone .arsc file or an .apk."""
    p = Path(path)
    if not p.exists():
        logger.error(f"File not found: {path}")
        return None
    if p.suffix.lower() == ".apk":
        return load_from_apk(path)
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# APK injection helper
# ---------------------------------------------------------------------------

def inject_arsc_into_apk(src_apk: str, arsc_data: bytes, dst_path: str) -> None:
    """
    Write a copy of src_apk to dst_path with resources.arsc replaced by arsc_data.

    All other entries are copied verbatim (their compress_type is preserved so
    APKSigner._zipalign() can re-process them correctly).  Entries that cannot
    be read (e.g. encrypted) are skipped with a warning.
    """
    injected = False
    with zipfile.ZipFile(src_apk, "r") as src:
        with zipfile.ZipFile(dst_path, "w", allowZip64=True) as dst:
            for info in src.infolist():
                if info.filename == "resources.arsc":
                    new_info = zipfile.ZipInfo(info.filename, info.date_time)
                    new_info.compress_type  = zipfile.ZIP_STORED
                    new_info.external_attr  = info.external_attr
                    dst.writestr(new_info, arsc_data)
                    injected = True
                else:
                    try:
                        raw = src.read(info.filename)
                        new_info = zipfile.ZipInfo(info.filename, info.date_time)
                        new_info.compress_type = info.compress_type
                        new_info.external_attr = info.external_attr
                        dst.writestr(new_info, raw)
                    except Exception as exc:
                        logger.warning(f"Skipping {info.filename}: {exc}")
            if not injected:
                # resources.arsc was absent in the source — add it
                new_info = zipfile.ZipInfo("resources.arsc")
                new_info.compress_type = zipfile.ZIP_STORED
                dst.writestr(new_info, arsc_data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="ArscFixer — parse, validate, fix, and optionally "
                    "re-inject / resign a resources.arsc (standalone or from an APK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python arscparser.py resources.arsc
    python arscparser.py app.apk
    python arscparser.py app.apk --fix --output fixed.arsc
    python arscparser.py app.apk --resign fixed_signed.apk
    python arscparser.py app.apk --fix --output fixed.arsc --resign fixed_signed.apk
        """,
    )
    ap.add_argument("path", help="Path to resources.arsc or an APK file")
    ap.add_argument(
        "--fix", action="store_true",
        help="Correct detected malformations",
    )
    ap.add_argument(
        "--output", "-o", default=None, metavar="ARSC_FILE",
        help="Write the fixed resources.arsc to this path (requires --fix)",
    )
    ap.add_argument(
        "--resign", default=None, metavar="APK_FILE",
        help="Inject the fixed resources.arsc back into the APK, zipalign, "
             "and sign it. Writes the resigned APK to APK_FILE. "
             "Input must be an .apk file. Implies --fix.",
    )
    ap.add_argument(
        "--log-level", "-l",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: WARNING)",
    )
    args = ap.parse_args()

    if args.output and not args.fix and not args.resign:
        ap.error("--output requires --fix")
    if args.fix and not args.output and not args.resign:
        ap.error("--fix requires --output or --resign")
    if args.resign and not args.path.lower().endswith(".apk"):
        ap.error("--resign requires an APK file as input")
    if args.resign and not _APKSIGNER_AVAILABLE:
        ap.error("--resign requires the apksigner module (apksigner.py not found)")

    # --resign implies --fix
    do_fix = args.fix or bool(args.resign)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )

    data = load_arsc(args.path)
    if data is None:
        raise SystemExit(1)

    print(f"\n{BLUE}=== resources.arsc parser ==={RESET}")
    print(f"Input : {args.path}")
    print(f"Size  : {len(data)} bytes\n")

    arsc   = ArscFixer(data)
    result = arsc.parse()

    if not result.issues:
        print(f"{GREEN}[OK] No issues detected.{RESET}")
    else:
        for issue in result.issues:
            print(issue)

    print()
    status = f"{GREEN}VALID{RESET}" if result.valid else f"{RED}INVALID{RESET}"
    print(f"Status   : {status}")
    print(f"Errors   : {result.error_count}")
    print(f"Warnings : {result.warning_count}")
    print(f"Packages : {len(result.packages)} declared={result.package_count_declared}")

    for pkg in result.packages:
        print(f"\n  Package 0x{pkg['id']:02x}  '{pkg['name']}'")
        print(f"    Type strings : {len(pkg['type_strings'])}")
        print(f"    Key strings  : {len(pkg['key_strings'])}")
        print(f"    TypeSpecs    : {len(pkg['type_specs'])}")
        for t in pkg["types"]:
            print(f"    Type[{t['id']:2d}] '{t['name']}'  entries={t['entry_count']}")

    # ── Fix ─────────────────────────────────────────────────────────────────
    if do_fix:
        print(f"\n{BLUE}=== applying fixes ==={RESET}")
        fixed_data, fixes = arsc.fix()

        if not fixes:
            print(f"{YELLOW}No fixable issues found — data unchanged.{RESET}")
        else:
            for f in fixes:
                print(f"  {GREEN}[FIX]{RESET} {f}")
            print(f"\n  {len(fixes)} fix(es) applied.")

        print(f"\n{BLUE}=== re-validating fixed data ==={RESET}")
        fixed_result = ArscFixer(fixed_data).parse()
        if not fixed_result.issues:
            print(f"{GREEN}[OK] Fixed data is clean.{RESET}")
        else:
            for issue in fixed_result.issues:
                print(issue)
        fixed_status = (f"{GREEN}VALID{RESET}" if fixed_result.valid
                        else f"{RED}STILL INVALID{RESET}")
        print(f"\nStatus after fix  : {fixed_status}")
        print(f"Remaining errors  : {fixed_result.error_count}")
        print(f"Remaining warnings: {fixed_result.warning_count}")

        if args.output:
            with open(args.output, "wb") as fh:
                fh.write(fixed_data)
            print(f"\nFixed resources.arsc → {args.output}")

    # ── Resign ──────────────────────────────────────────────────────────────
    if args.resign:
        print(f"\n{BLUE}=== injecting and signing APK ==={RESET}")

        with tempfile.TemporaryDirectory(prefix="arscparser_") as tmpdir:
            tmp_apk    = os.path.join(tmpdir, "intermediate.apk")
            inject_arsc_into_apk(args.path, fixed_data, tmp_apk)
            print(f"  Fixed resources.arsc injected into intermediate APK.")

            signer     = _APKSigner(logging.getLogger("apksigner"))
            signed_tmp = signer.sign(tmp_apk)   # → <tmpdir>/intermediate_resigned.apk
            shutil.copy2(signed_tmp, args.resign)

        print(f"  Resigned APK → {args.resign}")

    print()
    raise SystemExit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
