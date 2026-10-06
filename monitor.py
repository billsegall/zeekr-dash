"""
Background monitoring logic for vehicle position notifications.

Pure logic, no I/O. `CarMonitor.evaluate(status)` takes a raw vehicle-status dict
(as returned by `ZeekrClient.get_vehicle_status`) and returns a list of
(title, message) tuples to send. Holds transition state between calls so events
fire once per transition rather than every poll.

Home base and per-event toggles are *dynamic* (per-user preferences): the poller
calls `update_config(...)` each tick before `evaluate(...)`, so UI edits take effect
live. Changing the home base re-baselines the geofence silently (no spurious
arrive/leave). Tuning constants (hysteresis, movement threshold) are fixed at
construction.
"""

from __future__ import annotations

import logging
import math
from typing import Any

log = logging.getLogger(__name__)

EARTH_RADIUS_KM = 6371.0088

# engineStatus values that mean the car is parked / not driving.
_PARKED_ENGINE = {"engine-off", "", None}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class CarMonitor:
    """
    Evaluates movement and geofence rules across successive status reads.

    Movement: fires once on the not-moving -> moving transition (debounced), using
    speed / engineStatus / position displacement as motion signals. Independent of
    home base — always available.

    Geofence: only active when a home base is configured. Fires once on outside ->
    inside (arrive) and, when enabled, inside -> outside (leave), with a hysteresis
    buffer so a car parked near the boundary does not flap.

    The first reading establishes a silent baseline (no events) so a restart never
    emits a spurious "moved"/"arrived". Changing the home base via update_config()
    likewise re-baselines the geofence silently.
    """

    def __init__(self, *, hysteresis_km: float = 0.2, move_threshold_m: float = 100.0):
        self.hysteresis_km = hysteresis_km
        self.move_threshold_m = move_threshold_m

        # Dynamic config (set via update_config). No home => geofence disabled.
        self.home_lat: float | None = None
        self.home_lon: float | None = None
        self.radius_km: float | None = None
        self.notify_movement = True
        self.notify_arrive_home = True
        self.notify_leave_home = False

        # Transition state.
        self.initialized = False
        self.moving = False
        self.inside_home: bool | None = None
        self.last_lat: float | None = None
        self.last_lon: float | None = None
        self.last_update_time: int | None = None

    # -- config -------------------------------------------------------------

    def has_home(self) -> bool:
        return self.home_lat is not None and self.home_lon is not None and self.radius_km is not None

    def update_config(
        self,
        *,
        home_lat: float | None,
        home_lon: float | None,
        radius_km: float | None,
        notify_movement: bool,
        notify_arrive_home: bool,
        notify_leave_home: bool,
    ) -> None:
        """Apply per-user prefs. Re-baselines geofence silently if home changed."""
        self.notify_movement = notify_movement
        self.notify_arrive_home = notify_arrive_home
        self.notify_leave_home = notify_leave_home

        home_changed = (
            home_lat != self.home_lat
            or home_lon != self.home_lon
            or radius_km != self.radius_km
        )
        self.home_lat = home_lat
        self.home_lon = home_lon
        self.radius_km = radius_km

        if home_changed:
            if self.has_home() and self.last_lat is not None and self.last_lon is not None:
                self.inside_home = haversine_km(
                    self.last_lat, self.last_lon, self.home_lat, self.home_lon
                ) <= self.radius_km
            else:
                self.inside_home = None

    # -- parsing helpers ----------------------------------------------------

    @staticmethod
    def _parse_position(status: dict[str, Any]) -> tuple[float, float] | None:
        """Return (lat, lon) if present, trusted, and parseable; else None."""
        try:
            pos = status["basicVehicleStatus"]["position"]
        except (KeyError, TypeError):
            return None
        if pos is None:
            return None
        if str(pos.get("posCanBeTrusted", "1")) != "1":
            return None
        try:
            return float(pos["latitude"]), float(pos["longitude"])
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _parse_speed(status: dict[str, Any]) -> float:
        try:
            return float(status["basicVehicleStatus"].get("speed", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _parse_engine(status: dict[str, Any]) -> Any:
        return status.get("basicVehicleStatus", {}).get("engineStatus")

    @staticmethod
    def _parse_update_time(status: dict[str, Any]) -> int | None:
        try:
            return int(status["updateTime"])
        except (KeyError, TypeError, ValueError):
            return None

    # -- main evaluation ----------------------------------------------------

    def evaluate(self, status: dict[str, Any]) -> list[tuple[str, str]]:
        pos = self._parse_position(status)
        if pos is None:
            log.debug("monitor: no trusted position this tick, skipping")
            return []
        lat, lon = pos

        speed = self._parse_speed(status)
        engine = self._parse_engine(status)
        update_time = self._parse_update_time(status)
        fresh = update_time is not None and update_time != self.last_update_time

        events: list[tuple[str, str]] = []

        # First reading: silent baseline.
        if not self.initialized:
            self.initialized = True
            self.moving = speed > 0 or engine not in _PARKED_ENGINE
            if self.has_home():
                self.inside_home = haversine_km(lat, lon, self.home_lat, self.home_lon) <= self.radius_km
            self._remember(lat, lon, update_time)
            log.info(
                "monitor: baseline set (moving=%s, inside_home=%s)",
                self.moving, self.inside_home,
            )
            return events

        # --- Movement ------------------------------------------------------
        displacement_m = 0.0
        if self.last_lat is not None and self.last_lon is not None:
            displacement_m = haversine_km(lat, lon, self.last_lat, self.last_lon) * 1000.0

        is_moving = (
            speed > 0
            or engine not in _PARKED_ENGINE
            or (fresh and displacement_m > self.move_threshold_m)
        )

        if is_moving and not self.moving:
            if self.notify_movement:
                events.append((
                    "Zeekr: car started moving",
                    f"Now at {lat:.5f}, {lon:.5f}"
                    + (f" ({speed:.0f} km/h)" if speed > 0 else ""),
                ))
            self.moving = True
        elif self.moving and speed == 0 and not fresh:
            # Re-arm only once the car is confirmed parked AND asleep: speed 0 and
            # telemetry has stopped advancing (updateTime frozen). A transient stop
            # while the car is still awake (red light) keeps updateTime fresh, so we
            # stay "moving" and don't re-fire on the next pull-away.
            self.moving = False

        # --- Geofence (only if a home base is configured) ------------------
        if self.has_home():
            dist = haversine_km(lat, lon, self.home_lat, self.home_lon)
            if self.inside_home:
                # Require crossing the outer (n + hysteresis) ring to count as leaving.
                if dist > self.radius_km + self.hysteresis_km:
                    if self.notify_leave_home:
                        events.append((
                            "Zeekr: car left home",
                            f"{dist:.2f} km from home base",
                        ))
                    self.inside_home = False
            else:
                if dist <= self.radius_km:
                    if self.notify_arrive_home:
                        events.append((
                            "Zeekr: car arrived home",
                            f"Within {dist:.2f} km of home base",
                        ))
                    self.inside_home = True

        self._remember(lat, lon, update_time)
        return events

    def _remember(self, lat: float, lon: float, update_time: int | None) -> None:
        self.last_lat = lat
        self.last_lon = lon
        if update_time is not None:
            self.last_update_time = update_time
