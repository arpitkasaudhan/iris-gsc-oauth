"""Submitting URLs to the Indexing API, shared by the single and batch endpoints."""

import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import gsc_client, quota, token_service
from app.errors import AppError, ConnectionNotFound, NotPropertyOwner, QuotaExceeded, ReauthRequired, ScopeNotGranted
from app.gsc_client import GoogleAPIError
from app.models import ConnectionStatus, GoogleConnection, IndexRequest


@dataclass
class Submission:
    audit: IndexRequest
    conn: GoogleConnection
    site: dict
    result: dict

    @property
    def notify_time(self) -> str | None:
        meta = self.result.get("urlNotificationMetadata", {})
        latest = meta.get("latestUpdate") or meta.get("latestRemove") or {}
        return latest.get("notifyTime")


def active_connections(db: Session, user_id: str) -> list[GoogleConnection]:
    return list(
        db.scalars(
            select(GoogleConnection).where(
                GoogleConnection.user_id == user_id, GoogleConnection.status == ConnectionStatus.ACTIVE
            )
        )
    )


def resolve(db: Session, user_id: str, page_url: str, connection_id: str | None) -> tuple[GoogleConnection, dict]:
    """Find which of the user's Google accounts is a verified owner of ``page_url``."""
    if connection_id:
        conn = token_service.get_owned_connection(db, user_id, connection_id)
        return conn, gsc_client.resolve_owned_property(db, conn, page_url)

    conns = active_connections(db, user_id)
    if not conns:
        raise ConnectionNotFound("No active Google connection. Connect at /oauth/google/connect.")
    last_error: AppError | None = None
    for conn in conns:
        try:
            return conn, gsc_client.resolve_owned_property(db, conn, page_url)
        except (NotPropertyOwner, ScopeNotGranted, ReauthRequired) as exc:
            last_error = exc
    raise last_error  # type: ignore[misc]


def submit(
    db: Session, user_id: str, page_url: str, notification_type: str, connection_id: str | None = None
) -> Submission:
    """Check budget, resolve the owning account, publish, and audit. Raises on failure."""
    quota.ensure_available(db, user_id)

    audit = IndexRequest(user_id=user_id, url=page_url, notification_type=notification_type, outcome="failed")
    publishing = False
    try:
        conn, site = resolve(db, user_id, page_url, connection_id)
        audit.connection_id, audit.site_url = conn.id, site["siteUrl"]
        publishing = True
        result = gsc_client.publish_url_notification(db, conn, page_url, notification_type)
    except (AppError, GoogleAPIError) as exc:
        audit.http_status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        audit.detail = str(exc)
        # Only calls that reached Google's publish endpoint spend quota.
        audit.google_called = publishing and isinstance(exc, (GoogleAPIError, QuotaExceeded))
        db.add(audit)
        db.commit()
        raise

    audit.outcome, audit.http_status, audit.detail = "submitted", 200, json.dumps(result)
    audit.google_called = True
    db.add(audit)
    db.commit()
    return Submission(audit=audit, conn=conn, site=site, result=result)
