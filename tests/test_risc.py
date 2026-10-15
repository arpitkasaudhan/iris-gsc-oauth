import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import risc
from app.db import SessionLocal
from app.models import ConnectionStatus, GoogleConnection
from tests.conftest import CLIENT_ID, connect

ISSUER = "https://accounts.google.com/"
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def fake_google_keys(monkeypatch):
    monkeypatch.setattr(risc, "_signing_key", lambda _token: _private_key.public_key())
    monkeypatch.setattr(risc, "_issuer", lambda: ISSUER)


def _set(event_type: str, sub: str = "google-sub-1", jti: str | None = None, **payload) -> str:
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(time.time()),
        "jti": jti or uuid.uuid4().hex,
        "events": {event_type: {"subject": {"subject_type": "iss-sub", "iss": ISSUER, "sub": sub}, **payload}},
    }
    return jwt.encode(claims, _private_key, algorithm="RS256")


def _post(client, token: str):
    return client.post("/risc/events", content=token, headers={"Content-Type": "application/secevent+jwt"})


def _conn(conn_id):
    with SessionLocal() as db:
        return db.get(GoogleConnection, conn_id)


def test_tokens_revoked_event_wipes_grant(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    assert _post(client, _set(risc.EVT_TOKENS_REVOKED)).status_code == 202
    conn = _conn(conn_id)
    assert conn.status == ConnectionStatus.NEEDS_REAUTH
    assert conn.refresh_token_enc is None


def test_sessions_revoked_forces_a_refresh_but_keeps_grant(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    _post(client, _set(risc.EVT_SESSIONS_REVOKED))
    conn = _conn(conn_id)
    assert conn.status == ConnectionStatus.ACTIVE
    assert conn.access_token_enc is None and conn.refresh_token_enc is not None
    assert conn.security_flag == "sessions_revoked"


def test_account_hijacked_wipes_grant(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    _post(client, _set(risc.EVT_ACCOUNT_DISABLED, reason="hijacking"))
    assert _conn(conn_id).status == ConnectionStatus.NEEDS_REAUTH


def test_events_are_idempotent(client, google):
    connect(client, google)
    token = _set(risc.EVT_VERIFICATION, jti="same")
    _post(client, token)
    _post(client, token)
    with SessionLocal() as db:
        assert risc.handle_security_event(db, jwt.decode(token, options={"verify_signature": False})) == ["duplicate"]


def test_forged_event_rejected(client, google):
    conn_id = connect(client, google)["connection"]["id"]
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": int(time.time()),
            "jti": "x",
            "events": {risc.EVT_TOKENS_REVOKED: {"subject": {"sub": "google-sub-1"}}},
        },
        attacker_key,
        algorithm="RS256",
    )
    assert _post(client, forged).status_code == 400
    assert _conn(conn_id).status == ConnectionStatus.ACTIVE


def test_event_for_another_client_rejected(client, google):
    connect(client, google)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "someone-else",
            "iat": int(time.time()),
            "jti": "y",
            "events": {risc.EVT_VERIFICATION: {}},
        },
        _private_key,
        algorithm="RS256",
    )
    assert _post(client, token).status_code == 400
