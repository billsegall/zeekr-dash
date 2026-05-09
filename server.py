"""
Zeekr dashboard REST API server.
"""

import json
import logging
import os
import secrets
import time
from functools import wraps
from pathlib import Path
from threading import Lock

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash

from zeekr_ev_api import ZeekrClient
from zeekr_ev_api.exceptions import AuthException, ZeekrException

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

SECRETS_FILE = Path(__file__).parent / "zeekr_secrets.json"
SESSION_FILE = Path(__file__).parent / ".session.json"
ENV_FILE = Path(__file__).parent / ".env"

LOGIN_EMAIL = "bill@segall.net"
LOGIN_PASS_HASH = "scrypt:32768:8:1$3zAt5CrWbXwyLv19$833c236e3cef1e62c14baa28804ca7014d9d0132a9b12e516f437c7606333ccb0c04332088c635bcbc536d5b2f3aaf067eb39b71e4a99d0d7a83710a5bcdc526"
API_TOKEN = os.environ.get("API_TOKEN", "")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
CORS(app, supports_credentials=True)

# ---------------------------------------------------------------------------
# Client init
# ---------------------------------------------------------------------------

def _load_secrets() -> dict:
    with open(SECRETS_FILE) as f:
        d = json.load(f)
    return {
        "hmac_access_key": d["hmac_access_key"],
        "hmac_secret_key": d["hmac_secret_key"],
        "password_public_key": d["password_public_key"],
        "prod_secret": d["prod_secret"],
        "vin_key": d["vin_key"],
        "vin_iv": d["vin_iv"],
    }


def _build_client() -> ZeekrClient:
    secrets = _load_secrets()

    if SESSION_FILE.exists():
        with open(SESSION_FILE) as f:
            session = json.load(f)
        log.info("Resuming session from %s", SESSION_FILE.name)
        return ZeekrClient(session_data=session, **secrets)

    from dotenv import dotenv_values
    env = dotenv_values(ENV_FILE)
    email = env.get("ZEEKR_EMAIL")
    password = env.get("ZEEKR_PASSWORD")
    country_code = env.get("ZEEKR_COUNTRY_CODE", "AU")

    if not email or not password:
        raise RuntimeError("No session file and no credentials in .env — run connect.py first")

    log.info("No session file, logging in fresh...")
    client = ZeekrClient(username=email, password=password, country_code=country_code, **secrets)
    client.login()
    with open(SESSION_FILE, "w") as f:
        json.dump(client.export_session(), f, indent=2)
    return client


client = _build_client()
vehicles = client.get_vehicle_list()
if not vehicles:
    raise RuntimeError("No vehicles on this account")
VIN = vehicles[0].vin
log.info("Ready. VIN=%s", VIN)

# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------

_cache: dict = {}
_cache_lock = Lock()


def ttl_cache(seconds: int):
    def decorator(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = (fn.__name__, args, tuple(sorted(kwargs.items())))
            now = time.monotonic()
            with _cache_lock:
                entry = _cache.get(key)
                if entry and now - entry["ts"] < seconds:
                    return entry["data"]
            data = fn(*args, **kwargs)
            with _cache_lock:
                _cache[key] = {"data": data, "ts": time.monotonic()}
            return data
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Cached fetchers
# ---------------------------------------------------------------------------

@ttl_cache(30)
def fetch_status():
    return client.get_vehicle_status(VIN)


@ttl_cache(30)
def fetch_charging_status():
    return client.get_vehicle_charging_status(VIN)


@ttl_cache(60)
def fetch_charging_limit():
    return client.get_vehicle_charging_limit(VIN)


@ttl_cache(60)
def fetch_modes():
    return client.get_remote_control_state(VIN)


@ttl_cache(300)
def fetch_charge_plan():
    return client.get_charge_plan(VIN)


@ttl_cache(300)
def fetch_travel_plan():
    return client.get_travel_plan(VIN)


@ttl_cache(300)
def fetch_trips(size: int, days: int, end_time: int = 0):
    return client.get_journey_log(VIN, page_size=size, days_back=days, end_time=end_time)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _token_valid():
    if not API_TOKEN:
        return False
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return secrets.compare_digest(auth_header[7:], API_TOKEN)
    token_param = request.args.get("token", "")
    if token_param:
        return secrets.compare_digest(token_param, API_TOKEN)
    return False


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("logged_in") or _token_valid():
            return fn(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


# ---------------------------------------------------------------------------
# Error helper
# ---------------------------------------------------------------------------

def api_error(msg: str, status: int = 500):
    return jsonify({"error": msg}), status


def _invalidate_cache(*fn_names):
    with _cache_lock:
        for key in list(_cache.keys()):
            if key[0] in fn_names:
                del _cache[key]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/map")
def map_page():
    return send_from_directory("static", "map.html")


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/api/login")
def route_login():
    data = request.get_json() or {}
    email = data.get("email", "")
    password = data.get("password", "")
    if email == LOGIN_EMAIL and check_password_hash(LOGIN_PASS_HASH, password):
        session["logged_in"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid credentials"}), 401


@app.post("/api/logout")
def route_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/status")
@require_auth
def route_status():
    try:
        return jsonify(fetch_status())
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/charging")
@require_auth
def route_charging():
    try:
        return jsonify({
            "status": fetch_charging_status(),
            "limit": fetch_charging_limit(),
            "plan": fetch_charge_plan(),
        })
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/modes")
@require_auth
def route_modes():
    try:
        return jsonify(fetch_modes())
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/travel")
@require_auth
def route_travel():
    try:
        return jsonify(fetch_travel_plan())
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/trips")
@require_auth
def route_trips():
    size = request.args.get("size", 20, type=int)
    days = request.args.get("days", 30, type=int)
    end_time = request.args.get("end_time", 0, type=int)
    try:
        return jsonify(fetch_trips(size, days, end_time))
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/all")
@require_auth
def route_all():
    try:
        return jsonify({
            "vin": VIN,
            "status": fetch_status(),
            "charging": {
                "status": fetch_charging_status(),
                "limit": fetch_charging_limit(),
                "plan": fetch_charge_plan(),
            },
            "modes": fetch_modes(),
            "travel": fetch_travel_plan(),
        })
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.get("/api/chargeLevel")
@require_auth
def route_charge_level():
    try:
        status = fetch_status()
        level = status["additionalVehicleStatus"]["electricVehicleStatus"]["chargeLevel"]
        return jsonify({"chargeLevel": level})
    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.post("/api/control")
@require_auth
def route_control():
    data = request.get_json() or {}
    action = data.get("action")

    # Static action table: action -> (serviceID, command, setting)
    _STATIC = {
        "lock":              ("RDL", "start", {"serviceParameters": [{"key": "door",   "value": "all"}]}),
        "unlock":            ("RDU", "stop",  {"serviceParameters": [{"key": "door",   "value": "all"}]}),
        "flash":             ("RHL", "start", {"serviceParameters": [{"key": "rhl",    "value": "light-flash"}]}),
        "honk":              ("RHL", "start", {"serviceParameters": [{"key": "rhl",    "value": "horn-light-flash"}]}),
        "charge_start":      ("RCS", "start", {"serviceParameters": [{"key": "rcs.restart",   "value": "1"}]}),
        "charge_stop":       ("RCS", "stop",  {"serviceParameters": [{"key": "rcs.terminate",  "value": "1"}]}),
        "windows_open":      ("RWS", "start", {"serviceParameters": [{"key": "target", "value": "window"}]}),
        "windows_close":     ("RWS", "stop",  {"serviceParameters": [{"key": "target", "value": "window"}]}),
        "sunshade_open":     ("RWS", "start", {"serviceParameters": [{"key": "target", "value": "sunshade"}]}),
        "sunshade_close":    ("RWS", "stop",  {"serviceParameters": [{"key": "target", "value": "sunshade"}]}),
        "parking_comfort_off": ("PCM", "stop", {"serviceParameters": [{"key": "parking_comfortable", "value": "false"}]}),
        "defrost_on":        ("ZAF", "start", {"serviceParameters": [{"key": "DF", "value": "true"}, {"key": "DF.level", "value": "2"}]}),
        "defrost_off":       ("ZAF", "start", {"serviceParameters": [{"key": "DF", "value": "false"}]}),
        "steer_heat_on":     ("ZAF", "start", {"serviceParameters": [{"key": "SW", "value": "true"}, {"key": "SW.level", "value": "3"}, {"key": "SW.duration", "value": "15"}]}),
        "steer_heat_off":    ("ZAF", "start", {"serviceParameters": [{"key": "SW", "value": "false"}]}),
    }

    try:
        if action == "climate":
            ac_on = bool(data.get("on", False))
            if ac_on:
                temp = str(max(16, min(30, int(data.get("temp", 22)))))
                dur  = str(max(1,  min(15, int(data.get("duration", 15)))))
                setting = {"serviceParameters": [
                    {"key": "AC", "value": "true"},
                    {"key": "AC.temp",     "value": temp},
                    {"key": "AC.duration", "value": dur},
                ]}
            else:
                setting = {"serviceParameters": [{"key": "AC", "value": "false"}]}
            ok = client.do_remote_control(VIN, "start", "ZAF", setting)

        elif action == "charge_limit":
            limit = int(data.get("limit", 80))
            limit = round(max(50, min(100, limit)) / 5) * 5
            setting = {"serviceParameters": [
                {"key": "soc",          "value": str(limit * 10)},
                {"key": "rcs.setting",  "value": "1"},
                {"key": "altCurrent",   "value": "1"},
            ]}
            ok = client.do_remote_control(VIN, "start", "RCS", setting)

        elif action == "charge_plan":
            cmd        = data.get("cmd", "start")
            start_time = data.get("start_time", "")
            end_time   = data.get("end_time", "")
            ok = client.set_charge_plan(VIN, start_time=start_time, end_time=end_time, command=cmd)
            if ok:
                _invalidate_cache("fetch_charge_plan")
            return jsonify({"ok": ok})

        elif action == "travel_plan":
            cmd            = data.get("cmd", "start")
            scheduled_time = str(data.get("scheduled_time", ""))
            ac             = bool(data.get("ac", True))
            sw             = bool(data.get("sw", False))
            ok = client.set_travel_plan(
                VIN,
                command=cmd,
                scheduled_time=scheduled_time,
                ac_preconditioning=ac,
                steering_wheel_heating=sw,
            )
            if ok:
                _invalidate_cache("fetch_travel_plan")
            return jsonify({"ok": ok})

        elif action in _STATIC:
            service_id, command, setting = _STATIC[action]
            ok = client.do_remote_control(VIN, command, service_id, setting)

        elif action == "_raw":
            service_id = data.get("serviceId", "")
            command    = data.get("command", "start")
            setting    = data.get("setting", {})
            if not service_id:
                return api_error("serviceId required", 400)
            from zeekr_ev_api import network, const
            import json as _json
            extra_header = {"X-VIN": client._get_encrypted_vin(VIN)}
            body = {"command": command, "serviceId": service_id, "setting": setting}
            endpoint = const.CHARGE_CONTROL_URL if service_id == "RCS" else const.REMOTECONTROL_URL
            resp = network.appSignedPost(
                client,
                f"{client.region_login_server}{endpoint}",
                _json.dumps(body, separators=(",", ":")),
                extra_headers=extra_header,
            )
            log.info("_raw control response: %s", resp)
            return jsonify({"ok": resp.get("success", False), "raw": resp})

        else:
            return api_error("Unknown action", 400)

        if ok:
            _invalidate_cache("fetch_status", "fetch_charging_status", "fetch_charging_limit", "fetch_modes")
        return jsonify({"ok": ok})

    except (AuthException, ZeekrException) as e:
        return api_error(str(e))


@app.post("/api/refresh")
@require_auth
def route_refresh():
    """Force re-login and clear cache."""
    global client, VIN
    try:
        secrets = _load_secrets()
        from dotenv import dotenv_values
        env = dotenv_values(ENV_FILE)
        email = env.get("ZEEKR_EMAIL")
        password = env.get("ZEEKR_PASSWORD")
        country_code = env.get("ZEEKR_COUNTRY_CODE", "AU")
        if not email or not password:
            return api_error("No credentials in .env")
        client = ZeekrClient(username=email, password=password, country_code=country_code, **secrets)
        client.login()
        with open(SESSION_FILE, "w") as f:
            json.dump(client.export_session(), f, indent=2)
        vehicles = client.get_vehicle_list()
        VIN = vehicles[0].vin
        with _cache_lock:
            _cache.clear()
        log.info("Re-login OK. VIN=%s", VIN)
        return jsonify({"ok": True, "vin": VIN})
    except Exception as e:
        return api_error(str(e))


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8889, debug=False)
