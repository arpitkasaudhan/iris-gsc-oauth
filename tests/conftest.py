import base64
import os
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

_tmp = tempfile.mkdtemp()
os.environ.update(
    GOOGLE_CLIENT_ID="test-client.apps.googleusercontent.com",
    GOOGLE_CLIENT_SECRET="test-secret",
    GOOGLE_REDIRECT_URI="http://testserver/oauth/google/callback",
    TOKEN_ENCRYPTION_KEYS="k1:" + base64.urlsafe_b64encode(os.urandom(32)).decode(),
    SESSION_SECRET="test-session-secret",
    DATABASE_URL=f"sqlite:///{_tmp}/test.db",
    ENABLE_DEV_LOGIN="true",
    RISC_ENABLED="true",
)

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import google_oauth  # noqa: E402
from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
FULL_SCOPE = " ".join(google_oauth.SCOPES)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(google_oauth.time, "sleep", lambda _: None)


@pytest.fixture
def google():
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def client():
    with TestClient(app) as c:
        c.get("/dev/login", params={"user_id": "alice"})
        yield c


def make_id_token(sub: str = "google-sub-1", email: str = "owner@example.com") -> str:
    now = int(time.time())
    claims = {"iss": "https://accounts.google.com", "aud": CLIENT_ID, "sub": sub, "email": email, "iat": now, "exp": now + 3600}
    return jwt.encode(claims, "not-verified-in-this-flow-" + "x" * 32, algorithm="HS256")


def token_payload(access="ya29.access-1", refresh="1//refresh-1", scope=FULL_SCOPE, sub="google-sub-1", email="owner@example.com", expires_in=3599):
    body = {"access_token": access, "expires_in": expires_in, "scope": scope, "token_type": "Bearer", "id_token": make_id_token(sub, email)}
    if refresh:
        body["refresh_token"] = refresh
    return body


def connect(client: TestClient, google: respx.Router, **token_kwargs) -> dict:
    """Drive the full browser round trip: /connect -> Google -> /callback."""
    redirect = client.get("/oauth/google/connect", follow_redirects=False)
    assert redirect.status_code == 302
    state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
    google.post(google_oauth.TOKEN_URL).mock(return_value=httpx.Response(200, json=token_payload(**token_kwargs)))
    resp = client.get("/oauth/google/callback", params={"code": "4/auth-code", "state": state})
    assert resp.status_code == 200, resp.text
    return resp.json()
