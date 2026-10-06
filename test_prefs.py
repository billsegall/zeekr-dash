"""
Integration test for the /api/prefs endpoints via Flask's test client.

NOTE: importing server.py performs a real Zeekr login (resumes .session.json), so
this test needs network + valid session. It isolates users.json to a temp file so
it never mutates real data.
"""

import json
import os
import tempfile
from pathlib import Path


def test_prefs_roundtrip():
    import server

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"users": [{
        "id": "u1", "email": "t@t", "password_hash": "x",
        "is_admin": False, "can_write": True,
    }]}, tmp)
    tmp.close()
    server.USERS_FILE = Path(tmp.name)  # redirect _load_users/_save_users

    client = server.app.test_client()
    with client.session_transaction() as s:
        s["user_id"] = "u1"
        s["can_write"] = True

    # PUT a home base + toggle.
    r = client.put("/api/prefs", json={
        "home_lat": -27.48, "home_lon": 152.99,
        "home_radius_km": 2.0, "notify_leave_home": True,
    })
    assert r.status_code == 200, r.data
    p = r.get_json()
    assert p["home_lat"] == -27.48 and p["home_radius_km"] == 2.0
    assert p["notify_leave_home"] is True

    # GET reflects it.
    assert client.get("/api/prefs").get_json()["home_lat"] == -27.48

    # Persisted to disk.
    saved = json.load(open(tmp.name))["users"][0]
    assert saved["home_lat"] == -27.48 and saved["home_lon"] == 152.99

    # Clearing home -> null (disables geofence).
    r2 = client.put("/api/prefs", json={"home_lat": None, "home_lon": None})
    assert r2.get_json()["home_lat"] is None

    # Invalid coordinates rejected.
    assert client.put("/api/prefs", json={"home_lat": 200, "home_lon": 0}).status_code == 400
    # Invalid radius rejected.
    assert client.put("/api/prefs", json={"home_radius_km": -1}).status_code == 400

    os.unlink(tmp.name)
    print("PASS test_prefs_roundtrip")


if __name__ == "__main__":
    test_prefs_roundtrip()
    print("\n1/1 passed")
