"""Thin client for Google's OAuth 2.0 endpoints.

Deliberately written against the raw HTTP endpoints instead of
google-auth-oauthlib so every step of the flow is visible.
"""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt

from app.config import get_settings

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"

SCOPE_INDEXING = "https://www.googleapis.com/auth/indexing"
SCOPE_GSC_READONLY = "https://www.googleapis.com/auth/webmasters.readonly"

# Least privilege: read-only Search Console (list properties + ownership check,
# URL inspection) plus Indexing. openid+email identify WHICH Google account
# granted access, so reconnects update the same row instead of duplicating it.
SCOPES = ["openid", "email", SCOPE_GSC_READONLY, SCOPE_INDEXING]

_TRANSIENT_STATUSES = {500, 502, 503, 504}


class OAuthError(Exception):
    def __init__(self, status: int, error: str, description: str = ""):
        super().__init__(f"{status} {error}: {description}")
        self.status = status
        self.error = error
        self.description = description


class InvalidGrant(OAuthError):
    """Refresh token or auth code is dead: revoked, expired, or already used."""


class TransientOAuthError(OAuthError):
    """Google or the network hiccuped. Safe to retry, never a reason to drop a grant."""


@dataclass
class TokenResponse:
    access_token: str
    expires_in: int
    scope: str
    refresh_token: str | None = None
    id_token: str | None = None


def new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def build_authorization_url(state: str, code_challenge: str, login_hint: str | None = None) -> str:
    settings = get_settings()
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        # offline => Google returns a refresh token so we can act while the user is away.
        "access_type": "offline",
        # Google only issues a refresh token on the FIRST consent for a client.
        # Forcing the consent screen guarantees one on every (re)connect, which
        # is what makes recovery after invalid_grant possible.
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return f"{AUTH_URL}?{urlencode(params)}"


def _post_form(url: str, data: dict, retries: int = 2) -> httpx.Response:
    settings = get_settings()
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with httpx.Client(timeout=settings.http_timeout_seconds) as client:
                resp = client.post(url, data=data)
            if resp.status_code not in _TRANSIENT_STATUSES:
                return resp
            last_exc = TransientOAuthError(resp.status_code, "server_error", resp.text[:200])
        except httpx.TransportError as exc:
            last_exc = TransientOAuthError(0, "network_error", str(exc))
        if attempt < retries:
            time.sleep(0.5 * 2**attempt)
    raise last_exc  # type: ignore[misc]


def _parse_token_response(resp: httpx.Response) -> TokenResponse:
    body = resp.json() if resp.content else {}
    if resp.status_code != 200:
        error = body.get("error", "unknown_error")
        desc = body.get("error_description", "")
        cls = InvalidGrant if error == "invalid_grant" else OAuthError
        raise cls(resp.status_code, error, desc)
    return TokenResponse(
        access_token=body["access_token"],
        expires_in=int(body.get("expires_in", 3599)),
        scope=body.get("scope", ""),
        refresh_token=body.get("refresh_token"),
        id_token=body.get("id_token"),
    )


def exchange_code(code: str, code_verifier: str) -> TokenResponse:
    settings = get_settings()
    resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": settings.google_redirect_uri,
        },
    )
    return _parse_token_response(resp)


def refresh_access_token(refresh_token: str) -> TokenResponse:
    settings = get_settings()
    resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
        },
    )
    return _parse_token_response(resp)


def revoke_token(token: str) -> bool:
    """Revoke at Google. Returns True if revoked now OR already invalid.

    Revoking the refresh token also kills every access token minted from it,
    and removes the app from the user's myaccount.google.com/permissions list.
    """
    resp = _post_form(REVOKE_URL, {"token": token})
    if resp.status_code == 200:
        return True
    body = resp.json() if resp.content else {}
    if resp.status_code == 400 and body.get("error") == "invalid_token":
        return True
    raise OAuthError(resp.status_code, body.get("error", "revoke_failed"), body.get("error_description", ""))


def read_id_token(id_token: str) -> dict:
    """Read claims from an id_token received straight from TOKEN_URL.

    Google's docs allow skipping signature verification for an id_token that
    came over TLS directly from its token endpoint (not via the browser). We
    still check issuer, audience and expiry.
    """
    claims = jwt.decode(id_token, options={"verify_signature": False})
    if claims.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
        raise OAuthError(400, "invalid_id_token", "unexpected issuer")
    if claims.get("aud") != get_settings().google_client_id:
        raise OAuthError(400, "invalid_id_token", "audience mismatch")
    if int(claims.get("exp", 0)) < time.time() - 60:
        raise OAuthError(400, "invalid_id_token", "expired")
    return claims
