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
app.secret_key = secrets.token_hex(32)
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory("static", "index.html")


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
