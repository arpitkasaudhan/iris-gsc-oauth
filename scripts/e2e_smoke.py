"""Live smoke test: real uvicorn on a socket, real cookies and redirects, Google simulated with respx.

Walks the whole story over HTTP: login, consent redirect, callback, sites, index,
batch until the quota runs out, history, refresh, RISC events, disconnect,
reconnect, and finally checks that no secret reached the server logs.

Run from the repo root:  python scripts/e2e_smoke.py
"""

import base64
import io
import logging
import os
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"
tmp = tempfile.mkdtemp()
os.environ.update(
    GOOGLE_CLIENT_ID="e2e.apps.googleusercontent.com",
    GOOGLE_CLIENT_SECRET="GOCSPX-e2e-secret",
    GOOGLE_REDIRECT_URI=f"{BASE}/oauth/google/callback",
    TOKEN_ENCRYPTION_KEYS="k1:" + base64.urlsafe_b64encode(os.urandom(32)).decode(),
    SESSION_SECRET="e2e",
    DATABASE_URL=f"sqlite:///{tmp}/e2e.db",
    ENABLE_DEV_LOGIN="true",
    RISC_ENABLED="true",
    INDEXING_DAILY_QUOTA="5",
)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import jwt  # noqa: E402
import respx  # noqa: E402
import uvicorn  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from app import google_oauth, gsc_client, risc  # noqa: E402
from app.main import app  # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


# capture every log line the server writes, to prove redaction
log_buf = io.StringIO()
handler = logging.StreamHandler(log_buf)
logging.getLogger().addHandler(handler)

now = int(time.time())
id_token = jwt.encode(
    {
        "iss": "https://accounts.google.com",
        "aud": os.environ["GOOGLE_CLIENT_ID"],
        "sub": "sub-e2e",
        "email": "owner@acme.com",
        "iat": now,
        "exp": now + 3600,
    },
    "x" * 40,
    algorithm="HS256",
)
token_calls = []


def token_endpoint(request: httpx.Request):
    body = parse_qs(request.content.decode())
    token_calls.append(body["grant_type"][0])
    if body["grant_type"][0] == "authorization_code":
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.live-access-1",
                "refresh_token": "1//live-refresh",
                "expires_in": 3599,
                "scope": " ".join(google_oauth.SCOPES),
                "id_token": id_token,
            },
        )
    return httpx.Response(
        200, json={"access_token": "ya29.live-access-2", "expires_in": 3599, "scope": " ".join(google_oauth.SCOPES)}
    )


publish_count = 0


def publish(request: httpx.Request):
    global publish_count
    publish_count += 1
    import json

    url = json.loads(request.content)["url"]
    return httpx.Response(
        200,
        json={
            "urlNotificationMetadata": {
                "url": url,
                "latestUpdate": {"url": url, "type": "URL_UPDATED", "notifyTime": "2026-10-16T12:00:00Z"},
            }
        },
    )


rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
risc._signing_key = lambda _t: rsa_key.public_key()
risc._issuer = lambda: "https://accounts.google.com/"

with respx.mock(assert_all_called=False) as google:
    google.route(host="127.0.0.1").pass_through()
    google.post(google_oauth.TOKEN_URL).mock(side_effect=token_endpoint)
    google.post(google_oauth.REVOKE_URL).mock(return_value=httpx.Response(200))
    sites_route = google.get(gsc_client.SITES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "siteEntry": [
                    {"siteUrl": "sc-domain:acme.com", "permissionLevel": "siteOwner"},
                    {"siteUrl": "https://partner.org/", "permissionLevel": "siteFullUser"},
                ]
            },
        )
    )
    google.post(gsc_client.INDEXING_PUBLISH_URL).mock(side_effect=publish)
    google.get(url__startswith=gsc_client.INDEXING_METADATA_URL).mock(
        return_value=httpx.Response(
            200, json={"url": "https://acme.com/jobs/1", "latestUpdate": {"notifyTime": "2026-10-16T12:00:00Z"}}
        )
    )
    google.post(gsc_client.URL_INSPECTION_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "inspectionResult": {"indexStatusResult": {"verdict": "PASS", "coverageState": "Submitted and indexed"}}
            },
        )
    )

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="info"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)

    c = httpx.Client(base_url=BASE)
    browser = {"Accept": "text/html,application/xhtml+xml"}

    r = c.get("/health")
    check("health", r.status_code == 200)
    r = c.get("/")
    check("dashboard html", r.status_code == 200 and "GSC Indexing Console" in r.text)
    r = c.get("/openapi.json")
    paths = r.json()["paths"]
    check(
        "openapi lists all endpoints",
        all(
            p in paths
            for p in ["/gsc/index", "/gsc/index/batch", "/gsc/quota", "/risc/events", "/connections/{connection_id}"]
        ),
    )
    check("unauthenticated is 401", c.get("/connections").status_code == 401)
    check("me before login", c.get("/api/me").json()["user_id"] is None)

    c.get("/dev/login", params={"user_id": "arpit"})
    check("me after login", c.get("/api/me").json()["user_id"] == "arpit")

    r = c.get("/oauth/google/connect", headers=browser)
    loc = r.headers.get("location", "")
    q = parse_qs(urlsplit(loc).query)
    check("connect redirects to Google", r.status_code == 302 and loc.startswith(google_oauth.AUTH_URL))
    check(
        "offline + consent + PKCE S256",
        q["access_type"] == ["offline"] and q["prompt"] == ["consent"] and q["code_challenge_method"] == ["S256"],
    )

    r = c.get("/oauth/google/callback", params={"code": "4/live-code", "state": q["state"][0]}, headers=browser)
    check(
        "browser callback lands on dashboard",
        r.status_code == 303 and r.headers["location"] == "/?connected=owner%40acme.com",
    )
    replay = c.get("/oauth/google/callback", params={"code": "4/live-code", "state": q["state"][0]})
    check("state replay rejected", replay.status_code == 400)

    conns = c.get("/connections").json()
    conn_id = conns[0]["id"]
    check(
        "connection active with indexing scope",
        conns[0]["status"] == "active" and google_oauth.SCOPE_INDEXING in conns[0]["granted_scopes"],
    )
    check("no tokens in API output", "ya29" not in str(conns) and "1//" not in str(conns))

    sites = c.get("/gsc/sites").json()
    check("sites listed with permission", {s["permissionLevel"] for s in sites} == {"siteOwner", "siteFullUser"})

    r = c.post("/gsc/index", json={"url": "https://acme.com/jobs/1"})
    check(
        "index owned URL",
        r.status_code == 200 and r.json()["site_url"] == "sc-domain:acme.com" and r.json()["notify_time"],
    )
    r = c.post("/gsc/index", json={"url": "https://partner.org/page"})
    check(
        "full user refused (403 not_verified_owner)", r.status_code == 403 and r.json()["error"] == "not_verified_owner"
    )
    r = c.post("/gsc/index", json={"url": "not-a-url"})
    check("invalid URL is 422", r.status_code == 422)

    check("status endpoint", c.get("/gsc/index/status", params={"url": "https://acme.com/jobs/1"}).status_code == 200)
    r = c.post("/gsc/inspect", json={"url": "https://acme.com/jobs/1"})
    check(
        "inspect endpoint",
        r.status_code == 200 and r.json()["inspectionResult"]["indexStatusResult"]["verdict"] == "PASS",
    )

    q1 = c.get("/gsc/quota").json()
    check("quota counts only Google calls", q1["project_used"] == 1 and q1["remaining"] == 4, str(q1))

    urls = [f"https://acme.com/jobs/{i}" for i in range(2, 9)] + ["https://acme.com/jobs/2"]
    b = c.post("/gsc/index/batch", json={"urls": urls}).json()
    statuses = [x["status"] for x in b["results"]]
    check("batch dedupes and stops at quota", statuses == ["submitted"] * 4 + ["skipped"] * 3, str(statuses))
    check("quota exhausted after batch", b["quota"]["remaining"] == 0)
    r = c.post("/gsc/index", json={"url": "https://acme.com/jobs/99"})
    check("single index refused locally at 429", r.status_code == 429 and r.json()["source"] == "local_budget")
    check("publish calls == quota", publish_count == 5, str(publish_count))

    hist = c.get("/gsc/index/history").json()
    check(
        "history has every attempt incl. quota refusals",
        len(hist) == 8 and sum(h["http_status"] == 429 for h in hist) == 2,
        str([(h["outcome"], h["http_status"]) for h in hist]),
    )

    r = c.post(f"/connections/{conn_id}/refresh")
    check("forced refresh", r.status_code == 200 and token_calls.count("refresh_token") == 1)

    # RISC: sessions-revoked keeps grant, tokens-revoked wipes it
    def set_token(evt, jti):
        return jwt.encode(
            {
                "iss": "https://accounts.google.com/",
                "aud": os.environ["GOOGLE_CLIENT_ID"],
                "iat": now,
                "jti": jti,
                "events": {evt: {"subject": {"subject_type": "iss-sub", "sub": "sub-e2e"}}},
            },
            rsa_key,
            algorithm="RS256",
        )

    c.post("/risc/events", content=set_token(risc.EVT_SESSIONS_REVOKED, "j1"))
    conn = c.get("/connections").json()[0]
    check(
        "RISC sessions-revoked keeps grant", conn["status"] == "active" and conn["security_flag"] == "sessions_revoked"
    )

    other = httpx.Client(base_url=BASE)
    other.get("/dev/login", params={"user_id": "mallory"})
    check("other user cannot disconnect", other.delete(f"/connections/{conn_id}").status_code == 404)

    r = c.delete(f"/connections/{conn_id}")
    check("disconnect revokes", r.status_code == 200 and r.json()["status"] == "revoked")
    r = c.get("/gsc/sites", params={"connection_id": conn_id})
    check(
        "revoked connection blocked (409)",
        r.status_code == 409 and r.json()["reauth_url"] == "/oauth/google/connect",
        r.text,
    )

    # reconnect brings the same row back
    r = c.get("/oauth/google/connect")
    st = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = c.get("/oauth/google/callback", params={"code": "4/again", "state": st})
    check(
        "reconnect restores same row",
        r.status_code == 200
        and r.json()["connection"]["id"] == conn_id
        and r.json()["connection"]["status"] == "active",
    )

    c.post("/risc/events", content=set_token(risc.EVT_TOKENS_REVOKED, "j2"))
    check("RISC tokens-revoked wipes grant", c.get("/connections").json()[0]["status"] == "needs_reauth")
    check("forged RISC rejected", c.post("/risc/events", content="eyJhbGciOiJub25lIn0.e30.").status_code == 400)

    server.should_exit = True
    time.sleep(0.5)

logs = log_buf.getvalue()
leaks = [s for s in ("ya29.live-access", "1//live-refresh", "4/live-code", "GOCSPX-e2e-secret") if s in logs]
check("no secrets in server logs", not leaks and "[REDACTED]" in logs, f"leaked={leaks}")

failed = [r for r in results if not r[1]]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
