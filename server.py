"""
Zeekr dashboard REST API server.
"""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from threading import Lock, Timer

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

from consts import (
    ZEEKR_SERVICEID_PCM,
    ZEEKR_SERVICEID_RCS,
    ZEEKR_SERVICEID_RDC,
    ZEEKR_SERVICEID_RDL,
    ZEEKR_SERVICEID_RDL_2,
    ZEEKR_SERVICEID_RDO,
    ZEEKR_SERVICEID_RDU,
    ZEEKR_SERVICEID_RDU_2,
    ZEEKR_SERVICEID_RHL,
    ZEEKR_SERVICEID_RSM,
    ZEEKR_SERVICEID_RWS,
    ZEEKR_SERVICEID_ZAF,
)
from zeekr_ev_api import ZeekrClient
from zeekr_ev_api.exceptions import AuthException, ZeekrException
from notifier import build_notifier
from monitor import CarMonitor

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

SECRETS_FILE = Path(__file__).parent / "zeekr_secrets.json"
SESSION_FILE = Path(__file__).parent / ".session.json"
ENV_FILE = Path(__file__).parent / ".env"
USERS_FILE = Path(__file__).parent / "users.json"

API_TOKEN = os.environ.get("API_TOKEN", "")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
CORS(app, supports_credentials=True)

# ---------------------------------------------------------------------------
# User store
# ---------------------------------------------------------------------------

def _load_users() -> list:
    if not USERS_FILE.exists():
        return []
    with open(USERS_FILE) as f:
        return json.load(f).get("users", [])


def _save_users(users: list):
    with open(USERS_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)


def _find_user_by_email(email: str) -> dict | None:
    return next((u for u in _load_users() if u["email"] == email), None)


def _find_user_by_id(uid: str) -> dict | None:
    return next((u for u in _load_users() if u["id"] == uid), None)


def _user_public(u: dict) -> dict:
    return {k: v for k, v in u.items() if k != "password_hash"}

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

    from dotenv import dotenv_values
    env = dotenv_values(ENV_FILE)
    email = env.get("ZEEKR_EMAIL")
    password = env.get("ZEEKR_PASSWORD")
    country_code = env.get("ZEEKR_COUNTRY_CODE", "AU")

    if SESSION_FILE.exists():
        with open(SESSION_FILE) as f:
            session = json.load(f)
        log.info("Resuming session from %s", SESSION_FILE.name)
        return ZeekrClient(username=email, password=password, session_data=session, **secrets)

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

_charge_timer: Timer | None = None
_charge_timer_lock = Lock()


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
    """Fetch the journey log, keeping the reason when the API refuses the call.

    client.get_journey_log() swallows a refusal into an empty dict and logs why at
    DEBUG only, so at the service's INFO level a refusal looks identical to a
    vehicle with no trips and the table just renders empty. The request is issued
    here directly instead — the same pattern as the RCS control passthrough in
    route_control — because raising the library logger to DEBUG to read that
    message would also write the bearer token to the service log.

    Body fields mirror get_journey_log: time-window pagination, where end_time is
    the previous page's lastId - 1 and 0 means "now".
    """
    from zeekr_ev_api import network, const

    headers = client.logged_in_headers.copy()
    headers["X-VIN"] = client._get_encrypted_vin(VIN)
    end_ms = end_time if end_time > 0 else int(time.time() * 1000)
    body = {
        "currentPage": 1,
        "endTime": end_ms,
        "lastId": -1,
        "pageSize": size,
        "startTime": end_ms - days * 86_400_000,
    }
    resp = network.appSignedPost(
        client,
        f"{client.region_login_server}{const.JOURNEY_LOG_URL}",
        json.dumps(body, separators=(",", ":")),
        extra_headers=headers,
    )
    if resp.get("success"):
        return resp.get("data", {})

    code = resp.get("code", "unknown")
    msg = resp.get("msg") or "no detail returned by the API"
    log.warning("Trip log refused by Zeekr: %s %s", code, msg)
    # 079001 is the gateway's "interface not authorized" code, returned in Chinese.
    hint = (" — this endpoint is not authorized for these app credentials"
            if code == "079001" else "")
    # Reported in-band with HTTP 200: fetchAll() treats any non-ok trips response as
    # a whole-dashboard failure, so a 500 here would also blank the status panel.
    return {"error": f"Zeekr refused the trip log request ({code}): {msg}{hint}",
            "data": [], "total": 0, "pages": 0}


# ---------------------------------------------------------------------------
# Notifications / position monitor
# ---------------------------------------------------------------------------
#
# Two-level config:
#   - Per-user preferences (home base + event toggles) live in users.json and are
#     edited via /api/prefs by each logged-in user (canonical source of truth).
#   - .env holds deployment/transport config only: which user's prefs drive the
#     single Signal channel (NOTIFY_USER_EMAIL), tuning constants, SIGNAL_*.
# The poller reloads the notify-user's prefs each tick so UI edits apply live.

PREF_DEFAULTS = {
    "home_lat": None,
    "home_lon": None,
    "home_radius_km": 1.0,
    "notify_movement": True,
    "notify_arrive_home": True,
    "notify_leave_home": False,
}


def _user_prefs(user: dict) -> dict:
    return {k: user.get(k, default) for k, default in PREF_DEFAULTS.items()}


def _save_user_prefs(uid: str, updates: dict) -> dict | None:
    """Merge validated pref updates into a user record; returns the new prefs."""
    users = _load_users()
    user = next((u for u in users if u["id"] == uid), None)
    if not user:
        return None
    for k in PREF_DEFAULTS:
        if k in updates:
            user[k] = updates[k]
    _save_users(users)
    return _user_prefs(user)


notifier = build_notifier()
monitor: CarMonitor | None = None
if notifier is not None:
    monitor = CarMonitor(
        hysteresis_km=float(os.environ.get("HOME_HYSTERESIS_KM", "0.2") or 0.2),
        move_threshold_m=float(os.environ.get("MOVE_THRESHOLD_M", "100") or 100),
    )

NOTIFY_USER_EMAIL = os.environ.get("NOTIFY_USER_EMAIL", "").strip().lower()

# Floor poll interval at 30s: fetch_status() has a 30s TTL, so a shorter interval
# would just re-read the same cached value. If you ever poll faster, switch the
# poller to call client.get_vehicle_status(VIN) directly instead.
POLL_INTERVAL = max(30, int(os.environ.get("POLL_INTERVAL", "60") or 60))

_warned_no_notify_user = False


def _poller_loop():
    global _warned_no_notify_user
    log.info("Position poller started (interval=%ds, notify_user=%s)", POLL_INTERVAL, NOTIFY_USER_EMAIL)
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            user = _find_user_by_email(NOTIFY_USER_EMAIL)
            if user:
                p = _user_prefs(user)
                monitor.update_config(
                    home_lat=p["home_lat"], home_lon=p["home_lon"],
                    radius_km=p["home_radius_km"] if p["home_lat"] is not None else None,
                    notify_movement=p["notify_movement"],
                    notify_arrive_home=p["notify_arrive_home"],
                    notify_leave_home=p["notify_leave_home"],
                )
            elif not _warned_no_notify_user:
                log.warning("NOTIFY_USER_EMAIL=%s not found; movement-only.", NOTIFY_USER_EMAIL)
                _warned_no_notify_user = True
            status = fetch_status()
            for title, message in monitor.evaluate(status):
                log.info("notify: %s — %s", title, message)
                notifier.send(title, message)
        except Exception as exc:
            log.error("poller tick failed: %s", exc)


if notifier is not None and monitor is not None:
    from threading import Thread
    Thread(target=_poller_loop, daemon=True, name="position-poller").start()


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
        if session.get("user_id") or _token_valid():
            return fn(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


def require_write(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _token_valid():
            return fn(*args, **kwargs)
        if not session.get("user_id"):
            return jsonify({"error": "Unauthorized"}), 401
        if not session.get("can_write"):
            return jsonify({"error": "Forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Unauthorized"}), 401
        if not session.get("is_admin"):
            return jsonify({"error": "Forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Error helper
# ---------------------------------------------------------------------------

def api_error(msg: str, status: int = 500):
    return jsonify({"error": msg}), status


def _cancel_charge_timer():
    global _charge_timer
    with _charge_timer_lock:
        if _charge_timer is not None:
            _charge_timer.cancel()
            _charge_timer = None


def _arm_charge_timer(seconds: int, restore_plan: dict | None):
    global _charge_timer
    _cancel_charge_timer()
    def _fire():
        global _charge_timer
        try:
            if restore_plan and restore_plan.get("startTime") and restore_plan.get("command") == "start":
                log.info("charge_for timer fired — restoring previous plan %s→%s",
                         restore_plan["startTime"], restore_plan.get("endTime", ""))
                restored = client.set_charge_plan(
                    VIN,
                    start_time=restore_plan["startTime"],
                    end_time=restore_plan.get("endTime", ""),
                    command="start",
                    bc_cycle_active=restore_plan.get("bcCycleActive", False),
                    bc_temp_active=restore_plan.get("bcTempActive", False),
                )
                log.info("charge_for timer: restore result=%s", restored)
            else:
                log.info("charge_for timer fired — no prior plan, stopping")
                client.set_charge_plan(VIN, start_time="", end_time="", command="stop")
            _invalidate_cache("fetch_charge_plan")
        except Exception as exc:
            log.error("charge_for timer: failed to restore plan: %s", exc)
        with _charge_timer_lock:
            _charge_timer = None
    with _charge_timer_lock:
        _charge_timer = Timer(seconds, _fire)
        _charge_timer.daemon = True
        _charge_timer.start()
    log.info("charge_for timer armed for %ds", seconds)


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


@app.get("/admin")
def admin_page():
    return send_from_directory("static", "admin.html")


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
    user = _find_user_by_email(email)
    if user and check_password_hash(user["password_hash"], password):
        session.permanent = True
        session["user_id"] = user["id"]
        session["is_admin"] = user.get("is_admin", False)
        session["can_write"] = user.get("can_write", False)
        return jsonify({"ok": True, "is_admin": user.get("is_admin", False), "can_write": user.get("can_write", False)})
    return jsonify({"error": "Invalid credentials"}), 401


@app.post("/api/logout")
def route_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def route_me():
    if _token_valid():
        return jsonify({"ok": True, "is_admin": False, "can_write": True, "email": None})
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    user = _find_user_by_id(uid)
    if not user:
        session.clear()
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"ok": True, "is_admin": user.get("is_admin", False), "can_write": user.get("can_write", False), "email": user["email"]})


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


# ---------------------------------------------------------------------------
# Map tiles
# ---------------------------------------------------------------------------
# Browsers on this network get 403 "access blocked" and key-required pages
# straight from the public tile CDNs, while this host fetches the same tiles
# fine. So tiles are proxied: the page only ever talks to this server. That also
# lets us send the identifying User-Agent OpenStreetMap's tile usage policy asks
# for, and the disk cache keeps repeat views off their servers entirely.

TILE_CACHE = Path(__file__).parent / "tile_cache"
TILE_UPSTREAM = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
TILE_UA = "zeekr-dash/1.0 (+https://github.com/billsegall/zeekr-dash)"
TILE_MAX_ZOOM = 19


@app.get("/tiles/<int:z>/<int:x>/<int:y>.png")
@require_auth
def route_tile(z: int, x: int, y: int):
    # Bounded so the route can't be driven as a general-purpose fetcher; require_auth
    # keeps it off the open internet in the first place.
    if z > TILE_MAX_ZOOM or not (0 <= x < 2 ** z) or not (0 <= y < 2 ** z):
        return api_error("Tile out of range", 404)

    cached = TILE_CACHE / str(z) / str(x) / f"{y}.png"
    if not cached.exists():
        try:
            r = requests.get(
                TILE_UPSTREAM.format(z=z, x=x, y=y),
                headers={"User-Agent": TILE_UA},
                timeout=(5, 15),
            )
        except requests.RequestException as exc:
            log.warning("Tile fetch failed z=%s x=%s y=%s: %s", z, x, y, exc)
            return api_error("Tile fetch failed", 502)
        if r.status_code != 200 or not r.headers.get("Content-Type", "").startswith("image/"):
            log.warning("Tile upstream returned %s for z=%s x=%s y=%s", r.status_code, z, x, y)
            return api_error("Tile unavailable upstream", 502)
        cached.parent.mkdir(parents=True, exist_ok=True)
        # Write via a temp file so a concurrent request never serves a partial tile.
        tmp = cached.with_name(f"{cached.name}.{os.getpid()}.tmp")
        tmp.write_bytes(r.content)
        os.replace(tmp, cached)

    resp = send_from_directory(cached.parent, cached.name, mimetype="image/png")
    resp.headers["Cache-Control"] = "public, max-age=2592000"  # 30 days
    return resp


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
@require_write
def route_control():
    data = request.get_json() or {}
    action = data.get("action")

    # Static action table: action -> (serviceID, command, setting)
    _STATIC = {
        "lock":              (ZEEKR_SERVICEID_RDL, "start", {"serviceParameters": [{"key": "door",   "value": "all"}]}),
        "unlock":            (ZEEKR_SERVICEID_RDU, "stop",  {"serviceParameters": [{"key": "door",   "value": "all"}]}),
        "flash":             (ZEEKR_SERVICEID_RHL, "start", {"serviceParameters": [{"key": "rhl",    "value": "light-flash"}]}),
        "honk":              (ZEEKR_SERVICEID_RHL, "start", {"serviceParameters": [{"key": "rhl",    "value": "horn-light-flash"}]}),
        "charge_start":      (ZEEKR_SERVICEID_RCS, "start", {"serviceParameters": [{"key": "rcs.restart",   "value": "1"}]}),
        "charge_stop":       (ZEEKR_SERVICEID_RCS, "stop",  {"serviceParameters": [{"key": "rcs.terminate",  "value": "1"}]}),
        "windows_open":      (ZEEKR_SERVICEID_RWS, "start", {"serviceParameters": [{"key": "target", "value": "window"}]}),
        "windows_close":     (ZEEKR_SERVICEID_RWS, "stop",  {"serviceParameters": [{"key": "target", "value": "window"}]}),
        "sunshade_open":     (ZEEKR_SERVICEID_RWS, "start", {"serviceParameters": [{"key": "target", "value": "sunshade"}]}),
        "sunshade_close":    (ZEEKR_SERVICEID_RWS, "stop",  {"serviceParameters": [{"key": "target", "value": "sunshade"}]}),
        "boot_open":              (ZEEKR_SERVICEID_RDU,   "start", {"serviceParameters": [{"key": "target", "value": "trunk"}]}),
        "boot_close":             (ZEEKR_SERVICEID_RDL_2, "start", {"serviceParameters": [{"key": "target", "value": "trunk"}]}),
        "frunk_unlock":           (ZEEKR_SERVICEID_RDU,   "start", {"serviceParameters": [{"key": "target", "value": "hood"}]}),
        "charge_lid_ac_open":     (ZEEKR_SERVICEID_RDO,   "start", {"serviceParameters": [{"key": "target", "value": "front-charge-lid"}]}),
        "charge_lid_ac_close":    (ZEEKR_SERVICEID_RDC,   "stop",  {"serviceParameters": [{"key": "target", "value": "front-charge-lid"}]}),
        "charge_lid_dc_open":     (ZEEKR_SERVICEID_RDO,   "start", {"serviceParameters": [{"key": "target", "value": "back-charge-lid"}]}),
        "charge_lid_dc_close":    (ZEEKR_SERVICEID_RDC,   "stop",  {"serviceParameters": [{"key": "target", "value": "back-charge-lid"}]}),
        "parking_comfort_off": (ZEEKR_SERVICEID_PCM, "stop", {"serviceParameters": [{"key": "parking_comfortable", "value": "false"}]}),
        "sentinel_on":         (ZEEKR_SERVICEID_RSM, "start", {"serviceParameters": [{"key": "rsm", "value": "6"}]}),
        "sentinel_off":        (ZEEKR_SERVICEID_RSM, "stop",  {"serviceParameters": [{"key": "rsm", "value": "6"}]}),
        "defrost_on":        (ZEEKR_SERVICEID_ZAF, "start", {"serviceParameters": [{"key": "DF", "value": "true"}, {"key": "DF.level", "value": "2"}]}),
        "defrost_off":       (ZEEKR_SERVICEID_ZAF, "start", {"serviceParameters": [{"key": "DF", "value": "false"}]}),
        "steer_heat_on":     (ZEEKR_SERVICEID_ZAF, "start", {"serviceParameters": [{"key": "SW", "value": "true"}, {"key": "SW.level", "value": "3"}, {"key": "SW.duration", "value": "15"}]}),
        "steer_heat_off":    (ZEEKR_SERVICEID_ZAF, "start", {"serviceParameters": [{"key": "SW", "value": "false"}]}),
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
            ok = client.do_remote_control(VIN, "start", ZEEKR_SERVICEID_ZAF, setting)

        elif action == "charge_limit":
            limit = int(data.get("limit", 80))
            limit = round(max(50, min(100, limit)) / 5) * 5
            setting = {"serviceParameters": [
                {"key": "soc",          "value": str(limit * 10)},
                {"key": "rcs.setting",  "value": "1"},
                {"key": "altCurrent",   "value": "1"},
            ]}
            ok = client.do_remote_control(VIN, "start", ZEEKR_SERVICEID_RCS, setting)

        elif action == "charge_for":
            minutes = int(data.get("minutes", 60))
            minutes = max(15, min(600, minutes))
            prior_plan = client.get_charge_plan(VIN)
            now = datetime.now()
            end_dt = now + timedelta(minutes=minutes)
            pad = lambda n: str(n).zfill(2)
            start_time = f"{pad(now.hour)}:{pad(now.minute)}"
            end_time   = f"{pad(end_dt.hour)}:{pad(end_dt.minute)}"
            ok = client.set_charge_plan(VIN, start_time=start_time, end_time=end_time, command="start")
            if ok:
                _invalidate_cache("fetch_charge_plan")
                client.do_remote_control(VIN, "start", ZEEKR_SERVICEID_RCS,
                    {"serviceParameters": [{"key": "rcs.restart", "value": "1"}]})
                _arm_charge_timer(minutes * 60, prior_plan)
            return jsonify({"ok": ok})

        elif action == "charge_plan":
            cmd        = data.get("cmd", "start")
            start_time = data.get("start_time", "")
            end_time   = data.get("end_time", "")
            ok = client.set_charge_plan(VIN, start_time=start_time, end_time=end_time, command=cmd)
            if ok:
                _invalidate_cache("fetch_charge_plan")
                if cmd == "stop":
                    _cancel_charge_timer()
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
            if not session.get("is_admin") and not _token_valid():
                return api_error("Forbidden", 403)
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


@app.get("/api/admin/users")
@require_admin
def admin_list_users():
    return jsonify([_user_public(u) for u in _load_users()])


@app.post("/api/admin/users")
@require_admin
def admin_create_user():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return api_error("email and password required", 400)
    users = _load_users()
    if any(u["email"] == email for u in users):
        return api_error("email already exists", 400)
    user = {
        "id": secrets.token_hex(16),
        "email": email,
        "password_hash": generate_password_hash(password),
        "is_admin": bool(data.get("is_admin", False)),
        "can_write": bool(data.get("can_write", False)),
    }
    users.append(user)
    _save_users(users)
    return jsonify(_user_public(user)), 201


@app.put("/api/admin/users/<uid>")
@require_admin
def admin_update_user(uid):
    data = request.get_json() or {}
    users = _load_users()
    user = next((u for u in users if u["id"] == uid), None)
    if not user:
        return api_error("not found", 404)
    if "is_admin" in data and not data["is_admin"]:
        admin_count = sum(1 for u in users if u.get("is_admin") and u["id"] != uid)
        if admin_count == 0:
            return api_error("cannot remove last admin", 400)
    if data.get("password"):
        user["password_hash"] = generate_password_hash(data["password"])
    if "is_admin" in data:
        user["is_admin"] = bool(data["is_admin"])
    if "can_write" in data:
        user["can_write"] = bool(data["can_write"])
    _save_users(users)
    return jsonify(_user_public(user))


@app.delete("/api/admin/users/<uid>")
@require_admin
def admin_delete_user(uid):
    if session.get("user_id") == uid:
        return api_error("cannot delete yourself", 400)
    users = _load_users()
    user = next((u for u in users if u["id"] == uid), None)
    if not user:
        return api_error("not found", 404)
    if user.get("is_admin") and sum(1 for u in users if u.get("is_admin")) <= 1:
        return api_error("cannot delete last admin", 400)
    _save_users([u for u in users if u["id"] != uid])
    return jsonify({"ok": True})


@app.post("/api/refresh")
@require_admin
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


@app.get("/api/notify/test")
@require_admin
def route_notify_test():
    """Send a test notification to verify the configured transport."""
    if notifier is None:
        return api_error("Notifier not configured", 400)
    ok = notifier.send("Zeekr: test notification", "Notifications are wired up correctly.")
    return jsonify({"ok": ok})


@app.get("/api/prefs")
@require_auth
def route_get_prefs():
    """Return the current user's notification preferences (home base + toggles)."""
    uid = session.get("user_id")
    if not uid:
        return api_error("Login required for preferences", 401)
    user = _find_user_by_id(uid)
    if not user:
        return api_error("Unauthorized", 401)
    prefs = _user_prefs(user)
    prefs["is_notify_user"] = (user["email"].lower() == NOTIFY_USER_EMAIL)
    return jsonify(prefs)


@app.put("/api/prefs")
@require_auth
def route_put_prefs():
    """Update the current user's notification preferences."""
    uid = session.get("user_id")
    if not uid:
        return api_error("Login required for preferences", 401)
    data = request.get_json() or {}
    updates: dict = {}
    try:
        if "home_lat" in data and "home_lon" in data:
            if data["home_lat"] is None or data["home_lon"] is None:
                updates["home_lat"] = None
                updates["home_lon"] = None
            else:
                lat = float(data["home_lat"])
                lon = float(data["home_lon"])
                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    return api_error("Invalid coordinates", 400)
                updates["home_lat"] = lat
                updates["home_lon"] = lon
        if "home_radius_km" in data:
            r = float(data["home_radius_km"])
            if not (0 < r <= 1000):
                return api_error("Invalid radius", 400)
            updates["home_radius_km"] = r
        for key in ("notify_movement", "notify_arrive_home", "notify_leave_home"):
            if key in data:
                updates[key] = bool(data[key])
    except (TypeError, ValueError):
        return api_error("Invalid preference value", 400)

    prefs = _save_user_prefs(uid, updates)
    if prefs is None:
        return api_error("Unauthorized", 401)
    return jsonify(prefs)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8889, debug=False)
