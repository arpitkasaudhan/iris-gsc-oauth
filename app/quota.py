"""Local mirror of the Indexing API daily quota.

Google enforces the real limit and answers 429 when it is gone. Tracking it
ourselves means we can (a) refuse before spending a call, (b) show users how
much budget is left, and (c) stop one tenant from using up the whole
project's quota. Google resets the quota at midnight Pacific time, so our day
boundary is the same.

In a multi-worker deployment the count-then-call check can overshoot by a few
calls under heavy concurrency; Google's own 429 remains the hard stop.
"""

from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.errors import QuotaExceeded
from app.models import IndexRequest

PACIFIC = ZoneInfo("America/Los_Angeles")


def window(now_utc: datetime | None = None) -> tuple[datetime, datetime]:
    """Current quota day as naive-UTC [start, reset)."""
    now = (now_utc or datetime.now(UTC)).astimezone(PACIFIC)
    start = datetime.combine(now.date(), time.min, tzinfo=PACIFIC)
    reset = datetime.combine(now.date() + timedelta(days=1), time.min, tzinfo=PACIFIC)
    return (
        start.astimezone(UTC).replace(tzinfo=None),
        reset.astimezone(UTC).replace(tzinfo=None),
    )


def _used(db: Session, start: datetime, user_id: str | None = None) -> int:
    q = (
        select(func.count())
        .select_from(IndexRequest)
        .where(IndexRequest.google_called.is_(True), IndexRequest.created_at >= start)
    )
    if user_id is not None:
        q = q.where(IndexRequest.user_id == user_id)
    return db.scalar(q) or 0


def status(db: Session, user_id: str) -> dict:
    settings = get_settings()
    start, reset = window()
    project_used = _used(db, start)
    user_used = _used(db, start, user_id)
    project_left = max(settings.indexing_daily_quota - project_used, 0)
    user_left = (
        max(settings.indexing_daily_quota_per_user - user_used, 0) if settings.indexing_daily_quota_per_user else None
    )
    return {
        "project_limit": settings.indexing_daily_quota,
        "project_used": project_used,
        "project_remaining": project_left,
        "user_limit": settings.indexing_daily_quota_per_user or None,
        "user_used": user_used,
        "user_remaining": user_left,
        "remaining": project_left if user_left is None else min(project_left, user_left),
        "resets_at": reset.isoformat() + "Z",
    }


def ensure_available(db: Session, user_id: str) -> None:
    s = status(db, user_id)
    if s["remaining"] > 0:
        return
    scope = "your share of the" if s["user_remaining"] == 0 else "the project's"
    raise QuotaExceeded(
        f"Used all of {scope} daily Indexing API quota. Resets at {s['resets_at']}.",
        source="local_budget",
        resets_at=s["resets_at"],
    )
