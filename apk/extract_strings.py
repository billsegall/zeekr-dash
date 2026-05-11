#!/usr/bin/env python3
"""
Extract all string literals from Zeekr APK DEX files.

Writes one string per line to apk/strings.txt.
Pure stdlib — no external dependencies.

Usage:
    python apk/extract_strings.py [path/to/zeekr_base.apk]
"""

import struct
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_APK = REPO_ROOT / "zeekr_base.apk"
OUTPUT = Path(__file__).parent / "strings.txt"


def decode_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Decode ULEB128 integer. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7


def extract_strings_from_dex(data: bytes) -> list[str]:
    """Parse DEX string table and return all string literals."""
    if not data.startswith(b"dex\n"):
        return []

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
    strings = []

    for i in range(string_ids_size):
        data_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
        try:
            _utf16_size, str_start = decode_uleb128(data, data_off)
            null_pos = data.index(b"\x00", str_start)
            raw = data[str_start:null_pos]
            strings.append(raw.decode("utf-8", errors="replace"))
        except Exception:
            continue

    return strings


def main():
    apk_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_APK
    if not apk_path.exists():
        print(f"APK not found: {apk_path}", file=sys.stderr)
        sys.exit(1)

    all_strings: list[str] = []
    with zipfile.ZipFile(apk_path, "r") as z:
        dex_names = sorted(n for n in z.namelist() if n.endswith(".dex"))
        print(f"Found {len(dex_names)} DEX file(s): {', '.join(dex_names)}")
        for name in dex_names:
            data = z.read(name)
            found = extract_strings_from_dex(data)
            print(f"  {name}: {len(found):,} strings")
            all_strings.extend(found)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for s in all_strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    OUTPUT.write_text("\n".join(unique), encoding="utf-8")
    print(f"\nWrote {len(unique):,} unique strings → {OUTPUT}")


if __name__ == "__main__":
    main()
