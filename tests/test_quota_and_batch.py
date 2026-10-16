from datetime import UTC, datetime

import httpx
import pytest

from app import gsc_client, quota
from app.config import get_settings
from app.db import SessionLocal
from app.models import IndexRequest
from tests.conftest import connect

PUBLISH_OK = {"urlNotificationMetadata": {"latestUpdate": {"notifyTime": "2026-10-16T10:00:00Z"}}}


@pytest.fixture
def settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "indexing_daily_quota", 200)
    monkeypatch.setattr(s, "indexing_daily_quota_per_user", 0)
    return s


@pytest.fixture
def owned(client, google):
    """alice connected, owns sc-domain:example.com, publish succeeds."""
    connect(client, google)
    sites = google.get(gsc_client.SITES_URL).mock(
        return_value=httpx.Response(
            200, json={"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}
        )
    )
    publish = google.post(gsc_client.INDEXING_PUBLISH_URL).mock(return_value=httpx.Response(200, json=PUBLISH_OK))
    return sites, publish


def _spend(n: int, user_id: str = "alice") -> None:
    with SessionLocal() as db:
        for i in range(n):
            db.add(
                IndexRequest(
                    user_id=user_id,
                    url=f"https://example.com/{i}",
                    notification_type="URL_UPDATED",
                    outcome="submitted",
                    google_called=True,
                )
            )
        db.commit()


# ---------------------------------------------------------------- quota


def test_quota_day_follows_pacific_midnight():
    # 06:00 UTC on Oct 16 is 23:00 PDT on Oct 15, so the day started Oct 15 07:00 UTC.
    start, reset = quota.window(datetime(2026, 10, 16, 6, 0, tzinfo=UTC))
    assert start == datetime(2026, 10, 15, 7, 0)
    assert reset == datetime(2026, 10, 16, 7, 0)
    # after the November DST change Pacific is UTC-8
    start, _ = quota.window(datetime(2026, 12, 1, 12, 0, tzinfo=UTC))
    assert start == datetime(2026, 12, 1, 8, 0)


def test_exhausted_project_quota_refuses_before_calling_google(client, owned, settings):
    _, publish = owned
    settings.indexing_daily_quota = 3
    _spend(3, user_id="someone-else")

    resp = client.post("/gsc/index", json={"url": "https://example.com/a"})

    assert resp.status_code == 429
    assert resp.json()["source"] == "local_budget"
    assert publish.call_count == 0
    # the refusal is audited, and does not itself count against the budget
    history = client.get("/gsc/index/history").json()
    assert [(h["outcome"], h["http_status"]) for h in history] == [("failed", 429)]
    assert client.get("/gsc/quota").json()["project_used"] == 3


def test_per_user_cap(client, owned, settings):
    settings.indexing_daily_quota_per_user = 1
    assert client.post("/gsc/index", json={"url": "https://example.com/a"}).status_code == 200
    resp = client.post("/gsc/index", json={"url": "https://example.com/b"})
    assert resp.status_code == 429
    assert "your share" in resp.json()["message"]
    q = client.get("/gsc/quota").json()
    assert q["user_used"] == 1 and q["user_remaining"] == 0 and q["remaining"] == 0


def test_only_calls_that_reach_google_spend_quota(client, google, settings):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(
        return_value=httpx.Response(
            200, json={"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}
        )
    )
    google.post(gsc_client.INDEXING_PUBLISH_URL).mock(
        return_value=httpx.Response(403, json={"error": {"code": 403, "message": "Permission denied."}})
    )
    client.post("/gsc/index", json={"url": "https://other.org/x"})  # rejected locally, no property
    client.post("/gsc/index", json={"url": "https://example.com/x"})  # reached Google, got 403

    assert client.get("/gsc/quota").json()["project_used"] == 1


# ---------------------------------------------------------------- batch


def test_batch_reports_per_url_and_stops_at_quota(client, owned, settings):
    sites, publish = owned
    settings.indexing_daily_quota = 2
    urls = ["https://example.com/a", "https://other.org/b", "https://example.com/c", "https://example.com/d"]

    body = client.post("/gsc/index/batch", json={"urls": urls}).json()

    assert [r["status"] for r in body["results"]] == ["submitted", "failed", "submitted", "skipped"]
    assert body["results"][1]["error"] == "not_verified_owner"
    assert (body["submitted"], body["failed"], body["skipped"]) == (2, 1, 1)
    assert body["quota"]["remaining"] == 0
    assert publish.call_count == 2
    assert sites.call_count == 1  # ownership check served from cache after the first URL


def test_batch_google_429_skips_the_rest(client, google, settings):
    connect(client, google)
    google.get(gsc_client.SITES_URL).mock(
        return_value=httpx.Response(
            200, json={"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}
        )
    )
    publish = google.post(gsc_client.INDEXING_PUBLISH_URL).mock(
        side_effect=[
            httpx.Response(200, json=PUBLISH_OK),
            httpx.Response(429, json={"error": {"message": "Quota exceeded"}}),
        ]
    )
    body = client.post("/gsc/index/batch", json={"urls": [f"https://example.com/{i}" for i in range(4)]}).json()
    assert [r["status"] for r in body["results"]] == ["submitted", "skipped", "skipped", "skipped"]
    assert publish.call_count == 2


def test_batch_dedupes_urls(client, owned, settings):
    _, publish = owned
    body = client.post("/gsc/index/batch", json={"urls": ["https://example.com/a", "https://example.com/a"]}).json()
    assert len(body["results"]) == 1
    assert publish.call_count == 1


def test_batch_size_limit(client, owned, settings, monkeypatch):
    monkeypatch.setattr(settings, "batch_max_urls", 2)
    resp = client.post("/gsc/index/batch", json={"urls": [f"https://example.com/{i}" for i in range(3)]})
    assert resp.status_code == 400


# ---------------------------------------------------------------- sites cache


def test_sites_cached_for_ownership_checks_but_listing_is_fresh(client, owned, settings):
    sites, _ = owned
    client.post("/gsc/index", json={"url": "https://example.com/a"})
    client.post("/gsc/index", json={"url": "https://example.com/b"})
    assert sites.call_count == 1
    client.get("/gsc/sites")
    assert sites.call_count == 2
