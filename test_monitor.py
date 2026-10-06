"""Tests for monitor.py — haversine accuracy and CarMonitor transitions."""

from monitor import haversine_km, CarMonitor


def _status(lat, lon, *, speed=0, engine="engine-off", t=1000, trusted="1"):
    return {
        "updateTime": t,
        "basicVehicleStatus": {
            "speed": speed,
            "engineStatus": engine,
            "position": {
                "latitude": str(lat),
                "longitude": str(lon),
                "posCanBeTrusted": trusted,
            },
        },
    }


# --- haversine ----------------------------------------------------------

def test_haversine_brisbane_sydney():
    # Brisbane CBD -> Sydney CBD, known ~732 km.
    d = haversine_km(-27.4698, 153.0251, -33.8688, 151.2093)
    assert 720 < d < 745, d


def test_haversine_zero():
    assert haversine_km(-27.5, 153.0, -27.5, 153.0) == 0.0


def test_haversine_one_km_boundary():
    # ~1 km north: 1/111.32 deg latitude.
    home = (-27.5, 153.0)
    near = (-27.5 + 1.0 / 111.32, 153.0)
    d = haversine_km(*home, *near)
    assert abs(d - 1.0) < 0.01, d


# --- geofence -----------------------------------------------------------

def _monitor(home=(-27.5, 153.0), radius=1.0, **cfg):
    """Construct a monitor and apply dynamic config (home + toggles)."""
    m = CarMonitor(hysteresis_km=0.2, move_threshold_m=100)
    conf = dict(
        home_lat=home[0] if home else None,
        home_lon=home[1] if home else None,
        radius_km=radius if home else None,
        notify_movement=True,
        notify_arrive_home=True,
        notify_leave_home=True,
    )
    conf.update(cfg)
    m.update_config(**conf)
    return m


def test_first_reading_silent():
    m = _monitor()
    # Far away, moving — still no event on baseline.
    assert m.evaluate(_status(-28.0, 153.0, speed=60, engine="engine-on", t=1)) == []


def test_arrive_home_fires_once():
    m = _monitor()
    m.evaluate(_status(-28.0, 153.0, t=1))            # baseline: outside
    e1 = m.evaluate(_status(-27.5, 153.0, t=2))       # inside -> arrive
    e2 = m.evaluate(_status(-27.5005, 153.0, t=3))    # still inside -> nothing
    titles1 = [t for t, _ in e1]
    assert any("arrived home" in t for t in titles1), e1
    assert all("arrived" not in t for t, _ in e2), e2


def test_leave_home_needs_hysteresis():
    m = _monitor()
    m.evaluate(_status(-27.5, 153.0, t=1))            # baseline: inside
    # Just outside radius but within hysteresis (1.1 km) -> no leave yet.
    just_out = (-27.5 + 1.1 / 111.32, 153.0)
    e1 = m.evaluate(_status(*just_out, t=2))
    assert all("left home" not in t for t, _ in e1), e1
    # Beyond radius+hysteresis (1.3 km) -> leave fires.
    far = (-27.5 + 1.3 / 111.32, 153.0)
    e2 = m.evaluate(_status(*far, t=3))
    assert any("left home" in t for t, _ in e2), e2


def test_parked_at_boundary_no_flap():
    m = _monitor()
    boundary = (-27.5 + 1.0 / 111.32, 153.0)          # exactly ~1km from home
    m.evaluate(_status(*boundary, t=1))               # baseline parked at boundary
    events = []
    for i in range(5):                                # stays put, no movement/flap
        events += m.evaluate(_status(*boundary, t=2 + i))
    assert events == [], events


# --- movement -----------------------------------------------------------

def test_movement_fires_once_on_start():
    m = _monitor()
    m.evaluate(_status(-27.5, 153.0, speed=0, t=1))               # baseline parked
    e1 = m.evaluate(_status(-27.5, 153.0, speed=30, engine="engine-on", t=2))
    e2 = m.evaluate(_status(-27.49, 153.0, speed=40, engine="engine-on", t=3))
    assert any("started moving" in t for t, _ in e1), e1
    assert all("started moving" not in t for t, _ in e2), e2


def test_movement_redetects_after_sleep():
    # Car drives, then parks and goes to sleep (updateTime freezes) -> next drive
    # must re-fire.
    m = _monitor()
    m.evaluate(_status(-27.5, 153.0, speed=0, t=1))               # baseline parked
    m.evaluate(_status(-27.5, 153.0, speed=30, engine="engine-on", t=2))  # moving
    m.evaluate(_status(-27.5, 153.0, speed=0, engine="engine-off", t=3))  # just stopped (awake)
    m.evaluate(_status(-27.5, 153.0, speed=0, engine="engine-off", t=3))  # updateTime frozen -> asleep
    e = m.evaluate(_status(-27.5, 153.0, speed=25, engine="engine-on", t=4))  # drives again
    assert any("started moving" in t for t, _ in e), e


def test_no_refire_on_transient_stop():
    # Red light: car stops (speed 0) but stays awake (updateTime keeps advancing).
    # Must NOT re-arm, so pulling away does NOT fire a second "started moving".
    m = _monitor()
    m.evaluate(_status(-27.5, 153.0, speed=0, t=1))               # baseline parked
    e1 = m.evaluate(_status(-27.5, 153.0, speed=30, engine="engine-on", t=2))  # moving (fire)
    assert any("started moving" in t for t, _ in e1), e1
    m.evaluate(_status(-27.5, 153.0, speed=0, engine="engine-off", t=3))  # stop at light, awake
    e2 = m.evaluate(_status(-27.49, 153.0, speed=20, engine="engine-on", t=4))  # pull away
    assert all("started moving" not in t for t, _ in e2), e2


def test_update_home_silent_rebaseline():
    # Car sits far from original home (outside). Move home onto the car (now
    # inside) — must NOT emit an "arrived" event; it's a silent re-baseline.
    m = _monitor(home=(-27.5, 153.0), radius=1.0)
    m.evaluate(_status(-28.0, 153.0, t=1))            # baseline: outside
    m.evaluate(_status(-28.0, 153.0, t=2))            # still outside, no event
    m.update_config(home_lat=-28.0, home_lon=153.0, radius_km=1.0,
                    notify_movement=True, notify_arrive_home=True,
                    notify_leave_home=True)
    assert m.inside_home is True                      # re-baselined to inside
    e = m.evaluate(_status(-28.0, 153.0, t=3))        # no transition emitted
    assert all("arrived" not in t for t, _ in e), e


def test_movement_only_without_home():
    # No home configured: movement still fires, geofence silent.
    m = _monitor(home=None)
    assert m.has_home() is False
    m.evaluate(_status(-28.0, 153.0, speed=0, t=1))   # baseline parked
    e = m.evaluate(_status(-28.0, 153.0, speed=40, engine="engine-on", t=2))
    assert any("started moving" in t for t, _ in e), e
    assert all("home" not in t for t, _ in e), e


def test_untrusted_position_skipped():
    m = _monitor()
    m.evaluate(_status(-28.0, 153.0, t=1))            # baseline outside
    e = m.evaluate(_status(-27.5, 153.0, t=2, trusted="0"))  # arrive but untrusted
    assert e == [], e


if __name__ == "__main__":
    import sys
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for f in funcs:
        try:
            f()
            print(f"PASS {f.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {f.__name__}: {exc}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    sys.exit(1 if failed else 0)
