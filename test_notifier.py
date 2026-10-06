"""Tests for notifier.py — Signal payload shape and basic-auth path (mocked)."""

from unittest.mock import patch, MagicMock

from notifier import SignalNotifier


def _resp(status=201, text="OK"):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


def test_signal_payload_shape():
    n = SignalNotifier("http://localhost:8080/", "+61400000001",
                        ["+61400000002", "+61400000003"])
    with patch("notifier.requests.post", return_value=_resp()) as post:
        ok = n.send("Title", "Body line")
    assert ok is True
    args, kwargs = post.call_args
    assert args[0] == "http://localhost:8080/v2/send"   # trailing slash trimmed
    assert kwargs["json"] == {
        "number": "+61400000001",
        "recipients": ["+61400000002", "+61400000003"],
        "message": "Title\nBody line",
    }
    assert kwargs["auth"] is None


def test_signal_basic_auth():
    n = SignalNotifier("http://h:8080", "+1", ["+2"], user="u", password="p")
    with patch("notifier.requests.post", return_value=_resp()) as post:
        n.send("T", "")
    _, kwargs = post.call_args
    assert kwargs["auth"] == ("u", "p")
    assert kwargs["json"]["message"] == "T"             # no body -> title only


def test_signal_http_error_returns_false():
    n = SignalNotifier("http://h:8080", "+1", ["+2"])
    with patch("notifier.requests.post", return_value=_resp(status=400, text="bad")):
        assert n.send("T", "B") is False


def test_signal_network_error_swallowed():
    import requests
    n = SignalNotifier("http://h:8080", "+1", ["+2"])
    with patch("notifier.requests.post", side_effect=requests.RequestException("boom")):
        assert n.send("T", "B") is False


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
