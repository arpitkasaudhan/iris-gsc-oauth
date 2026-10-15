from datetime import timedelta

import httpx

from app import gsc_client, google_oauth
from app.db import SessionLocal, utcnow
from app.models import ConnectionStatus, GoogleConnection
from tests.conftest import connect

SITES = {"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}


def _expire_access_token(conn_id: str) -> None:
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        conn.access_token_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()


def test_expired_access_token_is_refreshed_transparently(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    _expire_access_token(conn_id)
    refresh = google.post(google_oauth.TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "ya29.fresh", "expires_in": 3599, "scope": " ".join(google_oauth.SCOPES)})
    )
    sites = google.get(gsc_client.SITES_URL).mock(return_value=httpx.Response(200, json=SITES))

    resp = client.get("/gsc/sites")

    assert resp.status_code == 200
    assert refresh.call_count == 2  # the code exchange, then exactly one refresh
    assert "grant_type=refresh_token" in refresh.calls.last.request.content.decode()
    assert sites.calls.last.request.headers["Authorization"] == "Bearer ya29.fresh"


def test_valid_access_token_is_reused_without_refresh(client, google):
    connect(client, google)
    refresh = google.post(google_oauth.TOKEN_URL)
    google.get(gsc_client.SITES_URL).mock(return_value=httpx.Response(200, json=SITES))
    client.get("/gsc/sites")
    client.get("/gsc/sites")
    # the only token-endpoint call is the original code exchange
    assert refresh.call_count == 1


def test_invalid_grant_flips_connection_to_needs_reauth(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    _expire_access_token(conn_id)
    google.post(google_oauth.TOKEN_URL).mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
    )

    resp = client.get("/gsc/sites", params={"connection_id": conn_id})

    assert resp.status_code == 409
    assert resp.json()["error"] == "google_reauth_required"
    assert resp.json()["reauth_url"] == "/oauth/google/connect"
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert conn.status == ConnectionStatus.NEEDS_REAUTH
        assert conn.refresh_token_enc is None and conn.access_token_enc is None


def test_transient_google_failure_does_not_drop_the_grant(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    _expire_access_token(conn_id)
    google.post(google_oauth.TOKEN_URL).mock(return_value=httpx.Response(503))

    resp = client.get("/gsc/sites", params={"connection_id": conn_id})

    assert resp.status_code == 502
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert conn.status == ConnectionStatus.ACTIVE
        assert conn.refresh_token_enc is not None


def test_reconnect_after_reauth_restores_connection(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        conn.status = ConnectionStatus.NEEDS_REAUTH
        conn.refresh_token_enc = conn.access_token_enc = None
        db.commit()
    again = connect(client, google, refresh="1//refresh-new")
    assert again["connection"]["id"] == conn_id
    assert again["connection"]["status"] == "active"


def test_rotated_refresh_token_is_stored(client, google):
    from app.crypto import get_cipher

    conn_id = connect(client, google)["connection"]["id"]
    google.post(google_oauth.TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "ya29.x", "expires_in": 3599, "refresh_token": "1//rotated"})
    )
    assert client.post(f"/connections/{conn_id}/refresh").status_code == 200
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert get_cipher().decrypt(conn.refresh_token_enc, conn.aad("refresh")) == "1//rotated"


def test_disconnect_revokes_at_google_then_wipes(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    revoke = google.post(google_oauth.REVOKE_URL).mock(return_value=httpx.Response(200))

    resp = client.delete(f"/connections/{conn_id}")

    assert resp.json()["status"] == "revoked"
    assert "token=1%2F%2Frefresh-1" in revoke.calls.last.request.content.decode()
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert conn.refresh_token_enc is None and conn.access_token_enc is None
    blocked = client.post("/gsc/index", json={"url": "https://example.com/a", "connection_id": conn_id})
    assert blocked.status_code == 409


def test_disconnect_when_already_revoked_at_google(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    google.post(google_oauth.REVOKE_URL).mock(return_value=httpx.Response(400, json={"error": "invalid_token"}))
    assert client.delete(f"/connections/{conn_id}").json()["status"] == "revoked"


def test_disconnect_with_google_down_keeps_token_for_retry(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    route = google.post(google_oauth.REVOKE_URL).mock(return_value=httpx.Response(503))

    assert client.delete(f"/connections/{conn_id}").json()["status"] == "revoke_pending"
    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert conn.refresh_token_enc is not None and conn.access_token_enc is None

    route.mock(return_value=httpx.Response(200))
    assert client.delete(f"/connections/{conn_id}").json()["status"] == "revoked"


def test_other_users_connection_is_invisible(client, google):
    from fastapi.testclient import TestClient

    from app.main import app

    conn_id = connect(client, google)["connection"]["id"]
    with TestClient(app) as bob:
        bob.get("/dev/login", params={"user_id": "bob"})
        assert bob.delete(f"/connections/{conn_id}").status_code == 404
