import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.db import init_db
from app.errors import AppError, app_error_handler
from app.gsc_client import GoogleAPIError
from app.routers import dev, gsc, oauth, risc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


settings = get_settings()
app = FastAPI(
    title="Google Search Console OAuth utility",
    description="Connect a user's Google account, keep the grant healthy, and request indexing on their behalf.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",  # lax, not strict: the cookie must survive Google's top-level redirect back
    https_only=settings.google_redirect_uri.startswith("https://"),
)
app.add_exception_handler(AppError, app_error_handler)


@app.exception_handler(GoogleAPIError)
async def google_api_error_handler(_: Request, exc: GoogleAPIError) -> JSONResponse:
    status = exc.status if 400 <= exc.status < 500 else 502
    return JSONResponse(
        status_code=status,
        content={"error": "google_api_error", "google_status": exc.status, "reason": exc.reason, "message": exc.message},
    )


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"ok": True}


app.include_router(oauth.router)
app.include_router(gsc.router)
app.include_router(risc.router)
app.include_router(dev.router)
