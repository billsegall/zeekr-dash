# TODO

## Testing needed

- **Sentinel on/off** (`RSM` + `rsm=6`) — just added to UI; needs real-world test.
- **Charging port open/close** (AC lid) — worked ~1/3 of the time before; should be reliable now that `_log` crash is fixed. Confirm.

## Known broken / unresolved

- **Boot close** — no working remote command. `RDL_2` accepted by API but car ignores it. `RDU_2` rejected outright. Boot close button removed from UI.
- **DC charge lid** (`RDO`/`RDC` + `target=back-charge-lid`) — buttons hidden from UI but serviceID unconfirmed. DC port may require a different target value or entirely different serviceID.
- **`RDU_2` rejected by API** — APK uses `RDU_2` for boot open but server returns `037000 parameter is incorrect`. Root cause unknown.

## Unknown serviceIDs — mode toggles

These modes display current state but have no on button (serviceID unknown):

| Mode | Notes |
|------|-------|
| GPS Tracking | |
| Journey Logging | |
| Camp Mode | |
| Overheat Guard | |
| Car Wash Mode | |
| Panic Alarm | |
| Visitor Mode | |
| Privacy Mode | |

Use `apk/find_patterns.py --pattern "<mode name>"` against decompiled source (`apk/src/`) to find serviceIDs.

## Upstream zeekr_ev_api

- PR #23 at `Fryyyyy/zeekr_ev_api` — verify it's clean (no debug logging commits) and merge-ready.

## Dashboard improvements

- Show sentinel status in security card (currently modes section is read-only; sentinel on/off state visible there but no direct indicator in the control row).
- Consider adding boot open/close status indicator — the car diagram shows doors but not tailgate state explicitly.
- Trip log: no pagination UI — loads latest N trips only.

## APK analysis

- Update `apk/README.md` with confirmed serviceID test results as testing completes.
- If a new Zeekr APK version ships, re-run `bash apk/setup.sh` to refresh decompiled source.
