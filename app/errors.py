from fastapi import Request
from fastapi.responses import JSONResponse


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, **extra):
        super().__init__(message)
        self.message = message
        self.extra = extra


class NotAuthenticated(AppError):
    status_code = 401
    code = "not_authenticated"


class InvalidOAuthState(AppError):
    status_code = 400
    code = "invalid_oauth_state"


class OAuthCallbackError(AppError):
    status_code = 400
    code = "oauth_callback_error"


class ConnectionNotFound(AppError):
    status_code = 404
    code = "connection_not_found"


class ReauthRequired(AppError):
    """The stored grant is unusable. Only the user can fix this, by reconnecting."""

    status_code = 409
    code = "google_reauth_required"

    def __init__(self, message: str, connection_id: str | None = None):
        super().__init__(message, connection_id=connection_id, reauth_url="/oauth/google/connect")


class ScopeNotGranted(AppError):
    status_code = 403
    code = "scope_not_granted"


class NotPropertyOwner(AppError):
    status_code = 403
    code = "not_verified_owner"


class GoogleUpstreamError(AppError):
    status_code = 502
    code = "google_upstream_error"


class QuotaExceeded(AppError):
    status_code = 429
    code = "google_quota_exceeded"


async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "message": exc.message, **exc.extra},
    )
