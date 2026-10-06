"""
Pluggable notification transports.

`build_notifier()` reads env config and returns a configured backend (or None if
unconfigured). Signal (signal-cli-rest-api) is the only backend today; the factory
is the single seam where Telegram/ntfy/Pushover get added later.
"""

from __future__ import annotations

import logging
import os

import requests

log = logging.getLogger(__name__)


class Notifier:
    """Base transport. Subclasses implement send()."""

    def send(self, title: str, message: str) -> bool:
        raise NotImplementedError


class SignalNotifier(Notifier):
    """
    Sends via a self-hosted signal-cli-rest-api daemon.

    POST {api_url}/v2/send
      {"number": <from>, "recipients": [<to>, ...], "message": "<title>\\n<body>"}
    Optional HTTP basic auth when user/pass are set (e.g. daemon behind a proxy).
    """

    def __init__(self, api_url: str, sender: str, recipients: list[str],
                 user: str = "", password: str = "", timeout: float = 10.0):
        self.api_url = api_url.rstrip("/")
        self.sender = sender
        self.recipients = recipients
        self.auth = (user, password) if user else None
        self.timeout = timeout

    def send(self, title: str, message: str) -> bool:
        body = {
            "number": self.sender,
            "recipients": self.recipients,
            "message": f"{title}\n{message}" if message else title,
        }
        try:
            resp = requests.post(
                f"{self.api_url}/v2/send",
                json=body,
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                log.error("Signal send failed: %s %s", resp.status_code, resp.text[:200])
                return False
            return True
        except requests.RequestException as exc:
            log.error("Signal send error: %s", exc)
            return False


def env_bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def build_notifier() -> Notifier | None:
    """Construct the configured notifier, or None if unconfigured/disabled."""
    if not env_bool("NOTIFY_ENABLED", True):
        log.info("Notifications disabled (NOTIFY_ENABLED).")
        return None

    service = os.environ.get("NOTIFY_SERVICE", "signal").strip().lower()

    if service == "signal":
        api_url = os.environ.get("SIGNAL_API_URL", "").strip()
        sender = os.environ.get("SIGNAL_FROM", "").strip()
        recipients = [r.strip() for r in os.environ.get("SIGNAL_TO", "").split(",") if r.strip()]
        if not (api_url and sender and recipients):
            log.warning("Signal notifier not configured (SIGNAL_API_URL/FROM/TO); disabled.")
            return None
        return SignalNotifier(
            api_url=api_url,
            sender=sender,
            recipients=recipients,
            user=os.environ.get("SIGNAL_USER", "").strip(),
            password=os.environ.get("SIGNAL_PASS", "").strip(),
        )

    log.warning("Unknown NOTIFY_SERVICE=%r; no notifier built.", service)
    return None
