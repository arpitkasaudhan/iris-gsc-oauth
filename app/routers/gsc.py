import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import gsc_client, token_service
from app.db import get_db
from app.deps import current_user_id
from app.errors import AppError, ConnectionNotFound, NotPropertyOwner, ReauthRequired, ScopeNotGranted
from app.gsc_client import GoogleAPIError
from app.models import ConnectionStatus, GoogleConnection, IndexRequest
from app.schemas import IndexRequestIn, IndexRequestOut, InspectIn

router = APIRouter(prefix="/gsc", tags=["search console"])


def _active_connections(db: Session, user_id: str) -> list[GoogleConnection]:
    return list(
        db.scalars(
            select(GoogleConnection).where(
                GoogleConnection.user_id == user_id, GoogleConnection.status == ConnectionStatus.ACTIVE
            )
        )
    )


def _resolve(db: Session, user_id: str, page_url: str, connection_id: str | None) -> tuple[GoogleConnection, dict]:
    """Find which of the user's Google accounts is a verified owner of ``page_url``."""
    if connection_id:
        conn = token_service.get_owned_connection(db, user_id, connection_id)
        return conn, gsc_client.resolve_owned_property(db, conn, page_url)

    conns = _active_connections(db, user_id)
    if not conns:
        raise ConnectionNotFound("No active Google connection. Connect at /oauth/google/connect.")
    last_error: AppError | None = None
    for conn in conns:
        try:
            return conn, gsc_client.resolve_owned_property(db, conn, page_url)
        except (NotPropertyOwner, ScopeNotGranted, ReauthRequired) as exc:
            last_error = exc
    raise last_error  # type: ignore[misc]


@router.get("/sites", summary="Search Console properties the user can see, with permission level")
def sites(
    connection_id: str | None = None, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> list[dict]:
    conns = (
        [token_service.get_owned_connection(db, user_id, connection_id)]
        if connection_id
        else _active_connections(db, user_id)
    )
    out = []
    for conn in conns:
        for site in gsc_client.list_sites(db, conn):
            out.append({**site, "connection_id": conn.id, "google_email": conn.google_email})
    return out


@router.post("/index", summary="Step 3: ask Google to (re)crawl a URL on the user's behalf")
def request_indexing(
    body: IndexRequestIn, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> IndexRequestOut:
    page_url = str(body.url)
    audit = IndexRequest(user_id=user_id, url=page_url, notification_type=body.type, outcome="failed")
    try:
        conn, site = _resolve(db, user_id, page_url, body.connection_id)
        audit.connection_id, audit.site_url = conn.id, site["siteUrl"]
        result = gsc_client.publish_url_notification(db, conn, page_url, body.type)
    except (AppError, GoogleAPIError) as exc:
        audit.http_status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        audit.detail = str(exc)
        db.add(audit)
        db.commit()
        raise

    audit.outcome, audit.http_status, audit.detail = "submitted", 200, json.dumps(result)
    db.add(audit)
    db.commit()
    meta = result.get("urlNotificationMetadata", {})
    latest = meta.get("latestUpdate") or meta.get("latestRemove") or {}
    return IndexRequestOut(
        request_id=audit.id,
        url=page_url,
        type=body.type,
        site_url=site["siteUrl"],
        connection_id=conn.id,
        google_email=conn.google_email,
        notify_time=latest.get("notifyTime"),
        google_response=result,
    )


@router.get("/index/status", summary="When Google last received a notification for this URL")
def indexing_status(
    url: str = Query(...),
    connection_id: str | None = None,
    user_id: str = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> dict:
    conn, _ = _resolve(db, user_id, url, connection_id)
    return gsc_client.get_notification_metadata(db, conn, url)


@router.post("/inspect", summary="URL Inspection API: Google's view of the page's index status")
def inspect(body: InspectIn, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)) -> dict:
    page_url = str(body.url)
    conn, site = _resolve(db, user_id, page_url, body.connection_id)
    return gsc_client.inspect_url(db, conn, page_url, site["siteUrl"])


@router.get("/index/history", summary="Audit log of indexing requests made for this user")
def history(user_id: str = Depends(current_user_id), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(
        select(IndexRequest).where(IndexRequest.user_id == user_id).order_by(IndexRequest.created_at.desc()).limit(100)
    )
    return [
        {
            "id": r.id,
            "url": r.url,
            "type": r.notification_type,
            "site_url": r.site_url,
            "outcome": r.outcome,
            "http_status": r.http_status,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
