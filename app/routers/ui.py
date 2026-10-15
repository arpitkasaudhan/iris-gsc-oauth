from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings

router = APIRouter(tags=["dashboard"])

_INDEX = Path(__file__).resolve().parent.parent / "static" / "index.html"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> HTMLResponse:
    return HTMLResponse(_INDEX.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})


@router.get("/api/me", summary="Who is logged in to this app (no Google data)")
def me(request: Request) -> dict:
    return {"user_id": request.session.get("user_id"), "dev_login_enabled": get_settings().enable_dev_login}
