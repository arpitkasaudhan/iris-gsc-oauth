import httpx
import pytest

from app import gsc_client, google_oauth
from app.gsc_client import match_property
from tests.conftest import connect

PUBLISH_OK = {
    "urlNotificationMetadata": {
        "url": "https://www.example.com/jobs/42",
        "latestUpdate": {"url": "https://www.example.com/jobs/42", "type": "URL_UPDATED", "notifyTime": "2026-10-16T10:00:00Z"},
    }
}


def _sites(*entries):
    return httpx.Response(200, json={"siteEntry": [{"siteUrl": u, "permissionLevel": p} for u, p in entries]})


def test_request_indexing_happy_path(client, google):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("sc-domain:example.com", "siteOwner")))
    publish = google.post(gsc_client.INDEXING_PUBLISH_URL).mock(return_value=httpx.Response(200, json=PUBLISH_OK))

    resp = client.post("/gsc/index", json={"url": "https://www.example.com/jobs/42"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["site_url"] == "sc-domain:example.com"
    assert body["notify_time"] == "2026-10-16T10:00:00Z"
    assert publish.calls.last.request.headers["Authorization"] == "Bearer ya29.access-1"
    assert b'"type":"URL_UPDATED"' in publish.calls.last.request.content.replace(b" ", b"")
    history = client.get("/gsc/index/history").json()
    assert history[0]["outcome"] == "submitted"


def test_full_user_is_not_enough(client, google):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("https://www.example.com/", "siteFullUser")))
    publish = google.post(gsc_client.INDEXING_PUBLISH_URL)

    resp = client.post("/gsc/index", json={"url": "https://www.example.com/jobs/42"})

    assert resp.status_code == 403
    assert resp.json()["error"] == "not_verified_owner"
    assert publish.call_count == 0
    assert client.get("/gsc/index/history").json()[0]["outcome"] == "failed"


def test_url_outside_any_property(client, google):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("sc-domain:example.com", "siteOwner")))
    resp = client.post("/gsc/index", json={"url": "https://other.org/page"})
    assert resp.status_code == 403


def test_indexing_scope_not_granted(client, google):
    connect(client, google, scope=f"openid email {google_oauth.SCOPE_GSC_READONLY}")
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("sc-domain:example.com", "siteOwner")))
    resp = client.post("/gsc/index", json={"url": "https://example.com/a"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "scope_not_granted"


def test_401_triggers_one_refresh_and_retry(client, google):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("sc-domain:example.com", "siteOwner")))
    google.post(google_oauth.TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "ya29.after-401", "expires_in": 3599})
    )
    publish = google.post(gsc_client.INDEXING_PUBLISH_URL).mock(
        side_effect=[httpx.Response(401, json={"error": {"code": 401, "message": "Invalid Credentials"}}), httpx.Response(200, json=PUBLISH_OK)]
    )

    resp = client.post("/gsc/index", json={"url": "https://example.com/a"})

    assert resp.status_code == 200
    assert publish.calls[-1].request.headers["Authorization"] == "Bearer ya29.after-401"


def test_quota_exhausted_surfaces_429(client, google):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(return_value=_sites(("sc-domain:example.com", "siteOwner")))
    google.post(gsc_client.INDEXING_PUBLISH_URL).mock(
        return_value=httpx.Response(429, json={"error": {"code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED"}})
    )
    resp = client.post("/gsc/index", json={"url": "https://example.com/a"})
    assert resp.status_code == 429
    assert resp.json()["error"] == "google_quota_exceeded"


def test_picks_the_google_account_that_owns_the_site(client, google):
    connect(client, google, sub="sub-a", email="a@agency.com", access="tok-a")
    connect(client, google, sub="sub-b", email="b@client.com", access="tok-b")

    def sites_for(request):
        if request.headers["Authorization"] == "Bearer tok-b":
            return _sites(("https://shop.client.com/", "siteOwner"))
        return _sites(("sc-domain:agency.com", "siteOwner"))

    google.get(gsc_client.SITES_URL).mock(side_effect=sites_for)
    google.post(gsc_client.INDEXING_PUBLISH_URL).mock(return_value=httpx.Response(200, json=PUBLISH_OK))

    resp = client.post("/gsc/index", json={"url": "https://shop.client.com/p/1"})

    assert resp.status_code == 200
    assert resp.json()["google_email"] == "b@client.com"


@pytest.mark.parametrize(
    ("sites", "url", "expected"),
    [
        ([("sc-domain:example.com", "siteOwner")], "https://blog.example.com/x", "sc-domain:example.com"),
        ([("sc-domain:example.com", "siteOwner")], "https://notexample.com/x", None),
        ([("https://example.com/", "siteOwner")], "http://example.com/x", None),
        (
            [("sc-domain:example.com", "siteOwner"), ("https://example.com/blog/", "siteOwner")],
            "https://example.com/blog/post",
            "https://example.com/blog/",
        ),
        (
            [("sc-domain:example.com", "siteOwner"), ("https://example.com/", "siteFullUser")],
            "https://example.com/x",
            "sc-domain:example.com",
        ),
    ],
)
def test_match_property(sites, url, expected):
    found = match_property([{"siteUrl": s, "permissionLevel": p} for s, p in sites], url)
    assert (found or {}).get("siteUrl") == expected
