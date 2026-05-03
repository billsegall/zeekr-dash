"""
Establish and verify connection to Zeekr EV API.
Prompts for credentials on first run, saves to .env.
"""

import getpass
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import dotenv_values, set_key
from zeekr_ev_api import ZeekrClient
from zeekr_ev_api.exceptions import AuthException

SECRETS_FILE = Path(__file__).parent / "zeekr_secrets.json"
ENV_FILE = Path(__file__).parent / ".env"
SESSION_FILE = Path(__file__).parent / ".session.json"


def load_secrets() -> tuple[dict, list[str]]:
    if not SECRETS_FILE.exists():
        print(f"ERROR: {SECRETS_FILE} not found", file=sys.stderr)
        sys.exit(1)
    with open(SECRETS_FILE) as f:
        data = json.load(f)
    base = {
        "hmac_access_key": data["hmac_access_key"],
        "hmac_secret_key": data["hmac_secret_key"],
        "password_public_key": data["password_public_key"],
        "vin_key": data["vin_key"],
        "vin_iv": data["vin_iv"],
    }
    candidates = data.get("prod_secret_candidates") or [data["prod_secret"]]
    return base, candidates


def get_credentials() -> tuple[str, str, str]:
    env = dotenv_values(ENV_FILE)
    email = env.get("ZEEKR_EMAIL") or os.environ.get("ZEEKR_EMAIL")
    password = env.get("ZEEKR_PASSWORD") or os.environ.get("ZEEKR_PASSWORD")
    country_code = env.get("ZEEKR_COUNTRY_CODE") or os.environ.get("ZEEKR_COUNTRY_CODE", "AU")

    if not email:
        email = input("Zeekr email: ").strip()
        set_key(ENV_FILE, "ZEEKR_EMAIL", email)

    if not password:
        password = getpass.getpass("Zeekr password: ")
        set_key(ENV_FILE, "ZEEKR_PASSWORD", password)

    return email, password, country_code


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    base_secrets, prod_candidates = load_secrets()
    email, password, country_code = get_credentials()

    print(f"\nConnecting as {email} (country_code={country_code})...")
    print(f"Trying {len(prod_candidates)} prod_secret candidate(s)...")

    client = None
    for i, prod_secret in enumerate(prod_candidates):
        print(f"  [{i+1}/{len(prod_candidates)}] prod_secret={prod_secret[:8]}...")
        try:
            c = ZeekrClient(
                username=email,
                password=password,
                country_code=country_code,
                prod_secret=prod_secret,
                **base_secrets,
            )
            c.login()
            client = c
            print(f"  SUCCESS with candidate {i+1}")
            break
        except AuthException as e:
            if "Signature authentication failed" in str(e):
                print(f"  signature fail, trying next...")
            else:
                raise

    if client is None:
        print("ERROR: All prod_secret candidates failed.", file=sys.stderr)
        sys.exit(1)

    print("Login successful.\n")

    vehicles = client.get_vehicle_list()
    if not vehicles:
        print("No vehicles found on this account.")
    else:
        print(f"Found {len(vehicles)} vehicle(s):")
        for v in vehicles:
            print(f"  VIN: {v.vin}")

    session_data = client.export_session()
    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f, indent=2)
    print(f"\nSession saved to {SESSION_FILE.name}")


if __name__ == "__main__":
    main()
