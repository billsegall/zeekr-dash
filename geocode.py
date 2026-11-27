"""
Reverse geocoding: coordinates -> suburb name, for human-friendly alerts.

Uses OpenStreetMap's public Nominatim service (no key). Its usage policy asks for
an identifying User-Agent and at most 1 request/second; alerts fire a handful of
times a day, and results are cached per ~100 m cell, so we stay far below that.
Any failure returns None so the caller can fall back to raw coordinates.
"""

from __future__ import annotations

import logging
import threading

import requests

log = logging.getLogger(__name__)

NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
USER_AGENT = "zeekr-dash/1.0 (+https://github.com/billsegall/zeekr-dash)"

# Most specific locality first. In Australia "suburb" is nearly always present;
# the rest cover rural/regional spots that only have a town or village.
_LOCALITY_KEYS = ("suburb", "town", "village", "hamlet", "city_district", "neighbourhood", "city")

_cache: dict[tuple[float, float], str | None] = {}
_lock = threading.Lock()


def _pick_locality(address: dict) -> str | None:
    for key in _LOCALITY_KEYS:
        value = (address.get(key) or "").strip()
        if value:
            return value
    return None


def suburb_for(lat: float, lon: float, timeout: float = 5.0) -> str | None:
    """Return the suburb/locality containing (lat, lon), or None if unknown."""
    key = (round(lat, 3), round(lon, 3))  # ~100 m cell
    with _lock:
        if key in _cache:
            return _cache[key]
    try:
        resp = requests.get(
            NOMINATIM_URL,
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 14, "addressdetails": 1},
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
        name = _pick_locality(resp.json().get("address") or {})
    except (requests.RequestException, ValueError) as exc:
        log.warning("reverse geocode failed: %s", exc)
        return None  # don't cache failures; retry next time
    with _lock:
        _cache[key] = name
    return name
