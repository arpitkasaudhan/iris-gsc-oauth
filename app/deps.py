from fastapi import Request

from app.errors import NotAuthenticated


def current_user_id(request: Request) -> str:
    """Our own app user. In the real product this is the existing login session;
    here a signed session cookie set by /dev/login stands in for it."""
    user_id = request.session.get("user_id")
    if not user_id:
        raise NotAuthenticated("Log in first (dev: GET /dev/login?user_id=alice).")
    return user_id
