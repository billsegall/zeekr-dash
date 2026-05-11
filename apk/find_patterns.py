#!/usr/bin/env python3
"""
Search APK string dump for patterns useful for reverse engineering.

Default (no args): prints serviceID candidates + API-related strings.
With --pattern REGEX: grep with ±N lines of context.
With --serviceids: focused serviceID candidate report.

Usage:
    python apk/find_patterns.py
    python apk/find_patterns.py --pattern "remoteControl"
    python apk/find_patterns.py --pattern "RCP|RCO|RCL" --context 5
    python apk/find_patterns.py --serviceids
"""

import argparse
import re
import sys
from pathlib import Path

STRINGS_FILE = Path(__file__).parent / "strings.txt"

# Strings we already know about — filter from "new candidates"
KNOWN_SERVICE_IDS = {"RCS", "RDL", "RDU", "RHL", "RWS", "PCM", "RSM", "ZAF"}

# Patterns for interesting API / control strings
API_PATTERNS = [
    r"serviceId",
    r"remoteControl",
    r"ms-remote-control",
    r"ms-charge-manage",
    r"/control",
    r"serviceParameters",
    r"\bcommand\b",
]


def load_strings() -> list[str]:
    if not STRINGS_FILE.exists():
        print(f"strings.txt not found. Run: python apk/extract_strings.py", file=sys.stderr)
        sys.exit(1)
    return STRINGS_FILE.read_text(encoding="utf-8").splitlines()


def grep_with_context(strings: list[str], pattern: str, context: int) -> None:
    rx = re.compile(pattern, re.IGNORECASE)
    matches = 0
    for i, line in enumerate(strings):
        if rx.search(line):
            start = max(0, i - context)
            end = min(len(strings), i + context + 1)
            print(f"--- match at line {i} ---")
            for j in range(start, end):
                marker = ">" if j == i else " "
                print(f"  {marker} [{j}] {strings[j]}")
            print()
            matches += 1
    print(f"{matches} match(es) for /{pattern}/")


def print_service_id_candidates(strings: list[str]) -> None:
    # 2-5 char ALL_CAPS strings (letters only, no digits)
    rx = re.compile(r"^[A-Z]{2,5}$")
    from collections import Counter
    counts: Counter = Counter()
    for s in strings:
        if rx.match(s):
            counts[s] += 1  # always 1 since strings.txt is deduplicated

    new = {s for s in counts if s not in KNOWN_SERVICE_IDS}
    print(f"=== ServiceID-shaped strings ({len(counts)} total, {len(new)} new) ===\n")
    print(f"Known (confirmed): {', '.join(sorted(KNOWN_SERVICE_IDS))}\n")
    print("New candidates:")
    for s in sorted(new):
        print(f"  {s}")


def print_api_strings(strings: list[str]) -> None:
    combined = re.compile("|".join(API_PATTERNS), re.IGNORECASE)
    matches = [s for s in strings if combined.search(s)]
    print(f"\n=== API/control strings ({len(matches)}) ===\n")
    for s in matches:
        print(f"  {s}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern", "-p", help="Regex to search for")
    parser.add_argument("--context", "-C", type=int, default=3, help="Lines of context (default 3)")
    parser.add_argument("--serviceids", action="store_true", help="Show serviceID candidates only")
    args = parser.parse_args()

    strings = load_strings()
    print(f"Loaded {len(strings):,} strings from {STRINGS_FILE}\n")

    if args.pattern:
        grep_with_context(strings, args.pattern, args.context)
    elif args.serviceids:
        print_service_id_candidates(strings)
    else:
        print_service_id_candidates(strings)
        print_api_strings(strings)


if __name__ == "__main__":
    main()
