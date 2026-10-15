from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi.testclient import TestClient

from app import google_oauth
from app.db import SessionLocal
from app.main import app
from app.models import GoogleConnection
from tests.conftest import connect, token_payload


def test_connect_redirects_to_google_with_offline_pkce_request(client):
    resp = client.get("/oauth/google/connect", follow_redirects=False)
    assert resp.status_code == 302
    url = urlsplit(resp.headers["location"])
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert f"{url.scheme}://{url.netloc}{url.path}" == google_oauth.AUTH_URL
    assert q["access_type"] == "offline"
    assert q["prompt"] == "consent"
    assert q["code_challenge_method"] == "S256"
    assert len(q["code_challenge"]) == 43
    assert google_oauth.SCOPE_INDEXING in q["scope"].split()
    assert len(q["state"]) >= 32


def test_connect_requires_app_login():
    with TestClient(app) as anon:
        assert anon.get("/oauth/google/connect", follow_redirects=False).status_code == 401


def test_callback_stores_tokens_encrypted(client, google):
    body = connect(client, google)
    assert body["connected"] is True
    assert body["missing_scopes"] == []
    conn_id = body["connection"]["id"]

    sent = google.calls.last.request.content.decode()
    assert "code_verifier=" in sent and "grant_type=authorization_code" in sent

    with SessionLocal() as db:
        conn = db.get(GoogleConnection, conn_id)
        assert conn.google_email == "owner@example.com"
        assert "1//refresh-1" not in conn.refresh_token_enc
        assert "ya29.access-1" not in conn.access_token_enc
        assert conn.refresh_token_enc.startswith("v1.k1.")


def test_state_is_single_use(client, google):
    redirect = client.get("/oauth/google/connect", follow_redirects=False)
    state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
    google.post(google_oauth.TOKEN_URL).mock(return_value=httpx.Response(200, json=token_payload()))
    assert client.get("/oauth/google/callback", params={"code": "c", "state": state}).status_code == 200
    replay = client.get("/oauth/google/callback", params={"code": "c", "state": state})
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_oauth_state"


def test_state_bound_to_the_user_who_started(client, google):
    redirect = client.get("/oauth/google/connect", follow_redirects=False)
    state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
    with TestClient(app) as mallory:
        mallory.get("/dev/login", params={"user_id": "mallory"})
        resp = mallory.get("/oauth/google/callback", params={"code": "c", "state": state})
    assert resp.status_code == 400
    assert "does not belong" in resp.json()["message"]


def test_unknown_state_rejected(client):
    resp = client.get("/oauth/google/callback", params={"code": "c", "state": "forged"})
    assert resp.status_code == 400


def test_user_cancels_consent(client):
    resp = client.get("/oauth/google/callback", params={"error": "access_denied", "state": "x"})
    assert resp.status_code == 400
    assert "access_denied" in resp.json()["message"]


def test_partial_consent_is_reported(client, google):
    body = connect(client, google, scope=f"openid email {google_oauth.SCOPE_GSC_READONLY}")
    assert body["missing_scopes"] == [google_oauth.SCOPE_INDEXING]


def test_reconnect_same_google_account_updates_one_row(client, google):
    first = connect(client, google)
    second = connect(client, google, access="ya29.access-2", refresh="1//refresh-2")
    assert first["connection"]["id"] == second["connection"]["id"]
    assert len(client.get("/connections").json()) == 1


def test_missing_refresh_token_fails_loudly(client, google):
    resp_redirect = client.get("/oauth/google/connect", follow_redirects=False)
    state = parse_qs(urlsplit(resp_redirect.headers["location"]).query)["state"][0]
    google.post(google_oauth.TOKEN_URL).mock(return_value=httpx.Response(200, json=token_payload(refresh=None)))
    resp = client.get("/oauth/google/callback", params={"code": "c", "state": state})
    assert resp.status_code == 400
    assert "no refresh token" in resp.json()["message"]
