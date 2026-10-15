from fastapi import APIRouter, HTTPException, Request

from app.config import get_settings

router = APIRouter(prefix="/dev", tags=["dev only"])


@router.get("/login", summary="Stand-in for the host product's login. Disabled unless ENABLE_DEV_LOGIN=true")
def dev_login(user_id: str, request: Request) -> dict:
    if not get_settings().enable_dev_login:
        raise HTTPException(404)
    request.session["user_id"] = user_id
    return {"logged_in_as": user_id, "next": "/oauth/google/connect"}


@router.get("/logout")
def dev_logout(request: Request) -> dict:
    request.session.clear()
    return {"logged_out": True}
