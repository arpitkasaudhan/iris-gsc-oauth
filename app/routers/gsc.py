from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import gsc_client, quota, token_service
from app.config import get_settings
from app.db import get_db
from app.deps import current_user_id
from app.errors import AppError, QuotaExceeded
from app.gsc_client import GoogleAPIError
from app.indexing_service import active_connections, resolve, submit
from app.models import IndexRequest
from app.schemas import BatchIndexIn, IndexRequestIn, IndexRequestOut, InspectIn

router = APIRouter(prefix="/gsc", tags=["search console"])


@router.get("/sites", summary="Search Console properties the user can see, with permission level")
def sites(
    connection_id: str | None = None, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> list[dict]:
    conns = (
        [token_service.get_owned_connection(db, user_id, connection_id)]
        if connection_id
        else active_connections(db, user_id)
    )
    out = []
    for conn in conns:
        for site in gsc_client.list_sites(db, conn, use_cache=False):
            out.append({**site, "connection_id": conn.id, "google_email": conn.google_email})
    return out


@router.post("/index", summary="Step 3: ask Google to (re)crawl a URL on the user's behalf")
def request_indexing(
    body: IndexRequestIn, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> IndexRequestOut:
    page_url = str(body.url)
    s = submit(db, user_id, page_url, body.type, body.connection_id)
    return IndexRequestOut(
        request_id=s.audit.id,
        url=page_url,
        type=body.type,
        site_url=s.site["siteUrl"],
        connection_id=s.conn.id,
        google_email=s.conn.google_email,
        notify_time=s.notify_time,
        google_response=s.result,
    )


@router.post("/index/batch", summary="Submit many URLs; one result per URL, stops cleanly at the quota")
def request_indexing_batch(
    body: BatchIndexIn, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> dict:
    limit = get_settings().batch_max_urls
    if len(body.urls) > limit:
        raise AppError(f"At most {limit} URLs per batch.")

    urls = list(dict.fromkeys(str(u) for u in body.urls))  # dedupe, keep order
    results: list[dict] = []
    quota_hit = False
    for url in urls:
        if quota_hit:
            results.append({"url": url, "status": "skipped", "error": "google_quota_exceeded"})
            continue
        try:
            s = submit(db, user_id, url, body.type, body.connection_id)
            results.append(
                {"url": url, "status": "submitted", "site_url": s.site["siteUrl"], "notify_time": s.notify_time}
            )
        except QuotaExceeded as exc:
            quota_hit = True
            results.append({"url": url, "status": "skipped", "error": exc.code, "message": exc.message})
        except AppError as exc:
            results.append({"url": url, "status": "failed", "error": exc.code, "message": exc.message})
        except GoogleAPIError as exc:
            results.append({"url": url, "status": "failed", "error": "google_api_error", "message": exc.message})

    counts = {k: sum(r["status"] == k for r in results) for k in ("submitted", "failed", "skipped")}
    return {**counts, "quota": quota.status(db, user_id), "results": results}


@router.get("/quota", summary="Indexing API budget left today (project and this user)")
def quota_status(user_id: str = Depends(current_user_id), db: Session = Depends(get_db)) -> dict:
    return quota.status(db, user_id)


@router.get("/index/status", summary="When Google last received a notification for this URL")
def indexing_status(
    url: str = Query(...),
    connection_id: str | None = None,
    user_id: str = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> dict:
    conn, _ = resolve(db, user_id, url, connection_id)
    return gsc_client.get_notification_metadata(db, conn, url)


@router.post("/inspect", summary="URL Inspection API: Google's view of the page's index status")
def inspect(body: InspectIn, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)) -> dict:
    page_url = str(body.url)
    conn, site = resolve(db, user_id, page_url, body.connection_id)
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
