# APK Analysis

Analysis workspace for the Zeekr Android APK.

## Files

| File | Purpose |
|------|---------|
| `extract_strings.py` | Parses DEX string tables → `strings.txt` (stdlib only) |
| `find_patterns.py` | Searches `strings.txt` for serviceIDs, API paths, patterns |
| `setup.sh` | Downloads jadx, runs extraction + full decompilation |

## Generated artifacts (gitignored)

| File/Dir | How to generate |
|----------|----------------|
| `strings.txt` | `python apk/extract_strings.py` |
| `src/` | `bash apk/setup.sh` (requires jadx download) |
| `jadx.jar` | Downloaded by `setup.sh` |

## Quick start

```bash
# Extract all strings (fast, ~5 sec):
python apk/extract_strings.py

# Search for patterns (requires strings.txt):
python apk/find_patterns.py                        # serviceID candidates + API strings
python apk/find_patterns.py --serviceids           # serviceID candidates only
python apk/find_patterns.py --pattern "remoteControl"
python apk/find_patterns.py --pattern "RCP|trunk|hood" --context 5

# Full decompile (slow, ~3 min, ~500MB output):
bash apk/setup.sh
# Then grep decompiled Java source:
grep -r "serviceId" apk/src/sources/
```

## Known serviceIDs

| ID | Meaning | Status |
|----|---------|--------|
| `RCS` | Remote Charge Service | ✅ working |
| `RDL` | Remote Door Lock | ✅ working |
| `RDU` | Remote Door Unlock (also frunk/boot open) | ✅ working |
| `RHL` | Remote Horn / Light | ✅ working |
| `RWS` | Remote Window / Sunshade | ✅ working |
| `PCM` | Parking Comfort Mode | ✅ working |
| `RSM` | Remote Sensing Mode | ✅ working |
| `ZAF` | ZEEKR Air Function (climate, defrost, steering heat) | ✅ working |
| `RDL` + `target=trunk` | Boot (tailgate) close | ❌ sends OK, car ignores |
| charge port open/close | Unknown | ❓ TBD |
| GPS Tracking toggle | Unknown | ❓ TBD |
| Journey Logging toggle | Unknown | ❓ TBD |
| Camp Mode toggle | Unknown | ❓ TBD |
| Overheat Guard toggle | Unknown | ❓ TBD |
| Car Wash Mode toggle | Unknown | ❓ TBD |
| Panic Alarm toggle | Unknown | ❓ TBD |
| Visitor Mode toggle | Unknown | ❓ TBD |
| Privacy Mode toggle | Unknown | ❓ TBD |
