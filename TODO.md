# TODO

## Testing needed

- **Sentinel on/off** (`RSM` + `rsm=6`) — just added to UI; needs real-world test.
- **Charging port open/close** (AC lid) — worked ~1/3 of the time before; should be reliable now that token-refresh crash is fixed (PR #29 merged). Confirm.

## Known broken / unresolved

- **Boot powered lift** — APK source confirms `RDU_2 start target=trunk` is the correct command. Server returns `037000 "parameter is incorrect"` for shared accounts. This is an account permission restriction — owner account only. Shared dashboard account cannot trigger it. Boot open button releases the latch only (`RDU start target=trunk`).
- **Boot close** — `RDL_2 start target=trunk` is accepted by server but car ignores it. No working remote close command exists.
- **DC charge port** — `RDO`/`RDC` + `target=back-charge-lid` confirmed in APK (`LOCK_BACK_CHARGE_LID`). Has no physical effect — serviceID or target may differ for this vehicle variant.

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

- PR #23 merged (trip pagination fix). PR #29 merged (password included in exported session — fixes token-refresh crash on session reload). Fork `billsegall/zeekr_ev_api` is up to date with upstream.

## Dashboard improvements

- Show sentinel status in security card (currently modes section is read-only; sentinel on/off state visible there but no direct indicator in the control row).
- Consider adding boot open/close status indicator — the car diagram shows doors but not tailgate state explicitly.
- Trip log: no pagination UI — loads latest N trips only.

## APK analysis

- Update `apk/README.md` with confirmed serviceID test results as testing completes.
- If a new Zeekr APK version ships, re-run `bash apk/setup.sh` to refresh decompiled source.
