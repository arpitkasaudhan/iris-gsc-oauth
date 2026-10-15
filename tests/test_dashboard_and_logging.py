import logging
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi.testclient import TestClient

from app import google_oauth
from app.log_redaction import RedactingFilter, redact
from app.main import app
from tests.conftest import token_payload

# ---------------------------------------------------------------- redaction


def test_redacts_google_tokens_and_oauth_fields():
    line = (
        "Authorization: Bearer ya29.a0AfH6SMBx-secret refresh=1//0gAbC-def "
        "body grant_type=refresh_token&refresh_token=1//xyz&client_secret=GOCSPX-abc "
        'json {"access_token": "opaque-token-value"} GET /oauth/google/callback?code=4/0AY0e-g7&state=s'
    )
    out = redact(line)
    for secret in (
        "ya29.a0AfH6SMBx-secret",
        "1//0gAbC-def",
        "1//xyz",
        "GOCSPX-abc",
        "opaque-token-value",
        "4/0AY0e-g7",
    ):
        assert secret not in out
    assert "grant_type=refresh_token" in out  # non-secret fields survive
    assert "state=s" in out


def test_harmless_text_is_untouched():
    line = "Google returned status code: 401 for connection abc"
    assert redact(line) == line


def test_filter_rewrites_formatted_records():
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1, "sent %s", ("Bearer ya29.secret",), None)
    RedactingFilter().filter(record)
    assert record.getMessage() == "sent Bearer [REDACTED]"


# ---------------------------------------------------------------- dashboard


def test_dashboard_served():
    with TestClient(app) as c:
        resp = c.get("/")
    assert resp.status_code == 200
    assert "GSC Indexing Console" in resp.text


def test_me_reports_session():
    with TestClient(app) as c:
        assert c.get("/api/me").json()["user_id"] is None
        c.get("/dev/login", params={"user_id": "alice"})
        assert c.get("/api/me").json()["user_id"] == "alice"


def test_browser_callback_redirects_to_dashboard(client, google):
    redirect = client.get("/oauth/google/connect", follow_redirects=False)
    state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
    google.post(google_oauth.TOKEN_URL).mock(return_value=httpx.Response(200, json=token_payload()))

    resp = client.get(
        "/oauth/google/callback",
        params={"code": "c", "state": state},
        headers={"Accept": "text/html,application/xhtml+xml"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/?connected=owner%40example.com"


def test_browser_callback_error_redirects_with_message(client):
    resp = client.get(
        "/oauth/google/callback",
        params={"error": "access_denied"},
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=oauth_callback_error" in resp.headers["location"]
