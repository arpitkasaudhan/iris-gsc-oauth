"""Google Cross-Account Protection (RISC) receiver logic.

Google pushes Security Event Tokens (signed JWTs) when something happens to a
user's Google account: tokens revoked, sessions revoked, account disabled for
hijacking, and so on. This is how we learn about a password reset or account
takeover WITHOUT waiting for the next refresh to fail.
"""

import logging
from functools import lru_cache

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import token_service
from app.config import get_settings
from app.models import ConnectionStatus, GoogleConnection, SecurityEvent

log = logging.getLogger(__name__)

RISC_CONFIG_URL = "https://accounts.google.com/.well-known/risc-configuration"

_RISC = "https://schemas.openid.net/secevent/risc/event-type/"
_OAUTH = "https://schemas.openid.net/secevent/oauth/event-type/"

EVT_TOKENS_REVOKED = _OAUTH + "tokens-revoked"
EVT_TOKEN_REVOKED = _OAUTH + "token-revoked"
EVT_SESSIONS_REVOKED = _RISC + "sessions-revoked"
EVT_ACCOUNT_DISABLED = _RISC + "account-disabled"
EVT_ACCOUNT_ENABLED = _RISC + "account-enabled"
EVT_CREDENTIAL_CHANGE_REQUIRED = _RISC + "account-credential-change-required"
EVT_VERIFICATION = _RISC + "verification"


class InvalidSecurityEvent(Exception):
    pass


@lru_cache
def _risc_config() -> dict:
    return httpx.get(RISC_CONFIG_URL, timeout=10).json()


@lru_cache
def _jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(_risc_config()["jwks_uri"])


def _signing_key(token: str):
    return _jwks_client().get_signing_key_from_jwt(token).key


def _issuer() -> str:
    return _risc_config()["issuer"]


def verify_security_event_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            _signing_key(token),
            algorithms=["RS256"],
            audience=get_settings().google_client_id,
            issuer=_issuer(),
            # SETs describe past events and carry no exp; Google's own sample
            # disables the expiry check. jti dedup below prevents replays.
            options={"verify_exp": False, "require": ["iss", "aud", "iat", "jti", "events"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidSecurityEvent(str(exc)) from exc


def _connections_for(db: Session, sub: str | None) -> list[GoogleConnection]:
    if not sub:
        return []
    return list(db.scalars(select(GoogleConnection).where(GoogleConnection.google_sub == sub)))


def handle_security_event(db: Session, claims: dict) -> list[str]:
    """Apply every event in the SET. Returns the actions taken (for logging/tests)."""
    jti = claims["jti"]
    if db.get(SecurityEvent, jti):
        return ["duplicate"]

    actions: list[str] = []
    subs: set[str | None] = set()
    for event_type, payload in claims["events"].items():
        subject = payload.get("subject", {})
        sub = subject.get("sub")
        conns = [c for c in _connections_for(db, sub) if c.status == ConnectionStatus.ACTIVE]

        if event_type == EVT_VERIFICATION:
            action = "verified"
        elif event_type in (EVT_TOKENS_REVOKED, EVT_TOKEN_REVOKED):
            # The grant is gone at Google. Drop our copy now rather than on the
            # next failing refresh, and tell the user to reconnect.
            for conn in conns:
                token_service.mark_needs_reauth(db, conn, "risc: tokens revoked")
            action = "tokens_wiped"
        elif event_type == EVT_ACCOUNT_DISABLED:
            reason = payload.get("reason")
            if reason == "hijacking":
                for conn in conns:
                    token_service.mark_needs_reauth(db, conn, "risc: account disabled (hijacking)")
                action = "tokens_wiped"
            else:
                for conn in conns:
                    token_service.expire_access_token(db, conn, f"account_disabled:{reason}")
                action = "access_token_expired"
        elif event_type == EVT_SESSIONS_REVOKED:
            # Fires on e.g. password reset with "sign out everywhere". Google
            # may or may not have killed our grant. Expire the cached access
            # token so the next call must refresh, which proves it either way.
            for conn in conns:
                token_service.expire_access_token(db, conn, "sessions_revoked")
            action = "access_token_expired"
        elif event_type == EVT_CREDENTIAL_CHANGE_REQUIRED:
            for conn in conns:
                token_service.expire_access_token(db, conn, "credential_change_required")
            action = "flagged"
        elif event_type == EVT_ACCOUNT_ENABLED:
            action = "noted"
        else:
            action = "ignored"

        actions.append(action)
        subs.add(sub)
        log.info("risc event %s for sub=%s -> %s", event_type, sub, action)

    db.add(
        SecurityEvent(
            jti=jti,
            event_type=",".join(claims["events"]),
            google_sub=",".join(sorted(s for s in subs if s)) or None,
            action_taken=",".join(actions),
        )
    )
    db.commit()
    return actions
