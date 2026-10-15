from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import risc
from app.config import get_settings
from app.db import get_db

router = APIRouter(tags=["cross-account protection"])


@router.post("/risc/events", status_code=202, summary="Receiver for Google RISC security event tokens")
async def receive(request: Request, db: Session = Depends(get_db)) -> Response:
    if not get_settings().risc_enabled:
        raise HTTPException(404)
    token = (await request.body()).decode().strip()
    try:
        claims = risc.verify_security_event_token(token)
    except risc.InvalidSecurityEvent as exc:
        raise HTTPException(400, f"invalid security event token: {exc}") from exc
    await run_in_threadpool(risc.handle_security_event, db, claims)
    return Response(status_code=202)
