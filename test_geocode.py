"""Tests for geocode.py — locality selection, caching and failure fallback (mocked)."""

from unittest import mock

import requests

import geocode


def _resp(address):
    r = mock.Mock()
    r.raise_for_status.return_value = None
    r.json.return_value = {"address": address}
    return r


def setup_function(_):
    geocode._cache.clear()


def test_prefers_suburb():
    with mock.patch.object(geocode.requests, "get",
                           return_value=_resp({"suburb": "Paddington", "city": "Brisbane"})):
        assert geocode.suburb_for(-27.46, 153.0) == "Paddington"


def test_falls_back_to_town():
    with mock.patch.object(geocode.requests, "get",
                           return_value=_resp({"town": "Maleny", "state": "Queensland"})):
        assert geocode.suburb_for(-26.76, 152.85) == "Maleny"


def test_caches_per_cell():
    with mock.patch.object(geocode.requests, "get",
                           return_value=_resp({"suburb": "Paddington"})) as get:
        geocode.suburb_for(-27.46001, 153.00001)
        geocode.suburb_for(-27.46002, 153.00002)      # same ~100 m cell
        assert get.call_count == 1


def test_network_error_returns_none_and_is_not_cached():
    with mock.patch.object(geocode.requests, "get",
                           side_effect=requests.ConnectionError("down")) as get:
        assert geocode.suburb_for(-27.46, 153.0) is None
        assert geocode.suburb_for(-27.46, 153.0) is None
        assert get.call_count == 2
