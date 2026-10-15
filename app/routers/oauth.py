from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import token_service
from app.db import get_db
from app.deps import current_user_id
from app.errors import AppError, OAuthCallbackError
from app.google_oauth import SCOPES
from app.models import GoogleConnection
from app.schemas import ConnectionOut

router = APIRouter(tags=["oauth"])


@router.get("/oauth/google/connect", summary="Step 1: send the user to Google's consent screen")
def connect(
    login_hint: str | None = Query(default=None, description="Pre-select a Google account by email"),
    user_id: str = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    return RedirectResponse(token_service.start_connect(db, user_id, login_hint), status_code=302)


@router.get("/oauth/google/callback", summary="Step 2: Google redirects back here with ?code&state")
def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    user_id: str = Depends(current_user_id),
    db: Session = Depends(get_db),
):
    # A real browser navigation lands back on the dashboard; API clients get JSON.
    browser = "text/html" in request.headers.get("accept", "")
    try:
        if error:
            # access_denied when the user clicks Cancel on the consent screen.
            raise OAuthCallbackError(f"Google returned error={error}.")
        if not code or not state:
            raise OAuthCallbackError("Missing code or state.")
        conn = token_service.complete_connect(db, user_id, code, state)
    except AppError as exc:
        if browser:
            return RedirectResponse(f"/?{urlencode({'error': exc.code, 'message': exc.message})}", status_code=303)
        raise
    missing = [s for s in SCOPES if s not in conn.scopes and s not in ("openid", "email")]
    if browser:
        params = {"connected": conn.google_email or ""}
        if missing:
            params["missing_scopes"] = " ".join(missing)
        return RedirectResponse(f"/?{urlencode(params)}", status_code=303)
    return {
        "connected": True,
        "connection": ConnectionOut.of(conn).model_dump(mode="json"),
        "missing_scopes": missing,
    }


@router.get("/connections", summary="List this user's Google connections and their health")
def list_connections(user_id: str = Depends(current_user_id), db: Session = Depends(get_db)) -> list[ConnectionOut]:
    rows = db.scalars(select(GoogleConnection).where(GoogleConnection.user_id == user_id))
    return [ConnectionOut.of(c) for c in rows]


@router.post("/connections/{connection_id}/refresh", summary="Force a token refresh (debug / health check)")
def force_refresh(
    connection_id: str, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> ConnectionOut:
    conn = token_service.get_owned_connection(db, user_id, connection_id)
    token_service.force_refresh(db, conn)
    return ConnectionOut.of(conn)


@router.delete("/connections/{connection_id}", summary="Disconnect: revoke at Google, then wipe locally")
def disconnect(
    connection_id: str, user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
) -> ConnectionOut:
    conn = token_service.get_owned_connection(db, user_id, connection_id)
    return ConnectionOut.of(token_service.disconnect(db, conn))
