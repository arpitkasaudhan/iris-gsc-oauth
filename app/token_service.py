"""The token lifecycle: connect, store, refresh, invalidate, revoke."""

import hashlib
import logging
import secrets
import threading
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import google_oauth
from app.config import get_settings
from app.crypto import get_cipher
from app.db import utcnow
from app.errors import ConnectionNotFound, GoogleUpstreamError, InvalidOAuthState, OAuthCallbackError, ReauthRequired
from app.models import ConnectionStatus, GoogleConnection, OAuthState

log = logging.getLogger(__name__)


def _hash_state(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


# ---------------------------------------------------------------- connect


def start_connect(db: Session, user_id: str, login_hint: str | None = None) -> str:
    state = secrets.token_urlsafe(32)
    verifier, challenge = google_oauth.new_pkce_pair()
    state_hash = _hash_state(state)
    db.add(
        OAuthState(
            state_hash=state_hash,
            user_id=user_id,
            code_verifier_enc=get_cipher().encrypt(verifier, f"state:{state_hash}"),
            expires_at=utcnow() + timedelta(seconds=get_settings().oauth_state_ttl_seconds),
        )
    )
    db.commit()
    return google_oauth.build_authorization_url(state, challenge, login_hint)


def _consume_state(db: Session, state: str, user_id: str) -> str:
    """Validate and burn the state. Returns the PKCE code_verifier."""
    state_hash = _hash_state(state)
    row = db.get(OAuthState, state_hash)
    if row is None:
        raise InvalidOAuthState("Unknown OAuth state.")
    if row.consumed_at is not None:
        raise InvalidOAuthState("OAuth state already used.")
    if row.expires_at < utcnow():
        raise InvalidOAuthState("OAuth state expired, start the connection again.")
    # Binding state to the session user stops login-CSRF: an attacker cannot
    # make a victim's browser finish the attacker's consent and link the
    # attacker's Google account to the victim's workspace (or vice versa).
    if row.user_id != user_id:
        raise InvalidOAuthState("OAuth state does not belong to this session.")
    row.consumed_at = utcnow()
    db.commit()
    return get_cipher().decrypt(row.code_verifier_enc, f"state:{state_hash}")


def complete_connect(db: Session, user_id: str, code: str, state: str) -> GoogleConnection:
    verifier = _consume_state(db, state, user_id)
    try:
        tokens = google_oauth.exchange_code(code, verifier)
    except google_oauth.TransientOAuthError as exc:
        raise GoogleUpstreamError("Google token endpoint unavailable, try again.") from exc
    except google_oauth.OAuthError as exc:
        raise OAuthCallbackError(f"Code exchange failed: {exc.error}") from exc

    if not tokens.id_token:
        raise OAuthCallbackError("Google did not return an id_token (openid scope missing).")
    claims = google_oauth.read_id_token(tokens.id_token)

    conn = db.scalar(
        select(GoogleConnection).where(
            GoogleConnection.user_id == user_id, GoogleConnection.google_sub == claims["sub"]
        )
    )
    if conn is None:
        conn = GoogleConnection(user_id=user_id, google_sub=claims["sub"])
        db.add(conn)
        db.flush()  # assigns conn.id, needed for the AAD below

    cipher = get_cipher()
    conn.google_email = claims.get("email")
    conn.granted_scopes = tokens.scope
    conn.access_token_enc = cipher.encrypt(tokens.access_token, conn.aad("access"))
    conn.access_token_expires_at = utcnow() + timedelta(seconds=tokens.expires_in)
    if tokens.refresh_token:
        conn.refresh_token_enc = cipher.encrypt(tokens.refresh_token, conn.aad("refresh"))
    if not conn.refresh_token_enc:
        # Only possible if consent was not forced. Without a refresh token we
        # would silently break in an hour, so fail loudly now.
        raise OAuthCallbackError("Google returned no refresh token. Reconnect and approve the consent screen.")
    conn.status = ConnectionStatus.ACTIVE
    conn.status_reason = None
    conn.security_flag = None
    conn.last_refreshed_at = utcnow()
    db.commit()
    return conn


# ---------------------------------------------------------------- refresh

_locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
_locks_guard = threading.Lock()


def _lock_for(connection_id: str) -> threading.Lock:
    # In-process single-flight. With several workers use a DB row lock
    # (SELECT ... FOR UPDATE) or a Redis lock instead; the logic is identical.
    with _locks_guard:
        return _locks[connection_id]


def _cached_token(conn: GoogleConnection, stale: str | None) -> str | None:
    if not conn.access_token_enc or not conn.access_token_expires_at:
        return None
    if conn.access_token_expires_at <= utcnow() + timedelta(seconds=get_settings().access_token_skew_seconds):
        return None
    token = get_cipher().decrypt(conn.access_token_enc, conn.aad("access"))
    return None if token == stale else token


def get_access_token(db: Session, conn: GoogleConnection, stale: str | None = None) -> str:
    """Return a usable access token, refreshing if needed.

    ``stale`` is a token Google just answered 401 to. If the stored token is
    still that one we refresh; if another request already refreshed it we
    simply use the new one (no double refresh).
    """
    if conn.status != ConnectionStatus.ACTIVE:
        raise ReauthRequired(f"Google connection is {conn.status.value}.", conn.id)

    token = _cached_token(conn, stale)
    if token:
        return token

    with _lock_for(conn.id):
        db.refresh(conn)
        if conn.status != ConnectionStatus.ACTIVE:
            raise ReauthRequired(f"Google connection is {conn.status.value}.", conn.id)
        token = _cached_token(conn, stale)
        if token:
            return token
        return _refresh(db, conn)


def force_refresh(db: Session, conn: GoogleConnection) -> str:
    if conn.status != ConnectionStatus.ACTIVE:
        raise ReauthRequired(f"Google connection is {conn.status.value}.", conn.id)
    with _lock_for(conn.id):
        return _refresh(db, conn)


def _refresh(db: Session, conn: GoogleConnection) -> str:
    cipher = get_cipher()
    if not conn.refresh_token_enc:
        mark_needs_reauth(db, conn, "no refresh token stored")
        raise ReauthRequired("No refresh token stored.", conn.id)

    refresh_token = cipher.decrypt(conn.refresh_token_enc, conn.aad("refresh"))
    try:
        tokens = google_oauth.refresh_access_token(refresh_token)
    except google_oauth.InvalidGrant as exc:
        # Terminal. Causes: user revoked access, password change on a grant
        # with Gmail scopes, 6 months unused, Testing-mode 7 day expiry,
        # Workspace session policy, over the 100-token limit, account
        # disabled. Retrying cannot fix any of them.
        mark_needs_reauth(db, conn, f"invalid_grant: {exc.description}")
        raise ReauthRequired("Google rejected the stored grant. Ask the user to reconnect.", conn.id) from exc
    except google_oauth.TransientOAuthError as exc:
        # Do NOT touch the grant on a 5xx or timeout.
        raise GoogleUpstreamError("Google token endpoint unavailable, try again.") from exc

    conn.access_token_enc = cipher.encrypt(tokens.access_token, conn.aad("access"))
    conn.access_token_expires_at = utcnow() + timedelta(seconds=tokens.expires_in)
    if tokens.refresh_token:  # Google may rotate; always keep the newest.
        conn.refresh_token_enc = cipher.encrypt(tokens.refresh_token, conn.aad("refresh"))
    elif cipher.needs_rotation(conn.refresh_token_enc):
        conn.refresh_token_enc = cipher.encrypt(refresh_token, conn.aad("refresh"))
    if tokens.scope:
        conn.granted_scopes = tokens.scope
    conn.last_refreshed_at = utcnow()
    db.commit()
    log.info("refreshed access token for connection %s", conn.id)
    return tokens.access_token


# ---------------------------------------------------------------- invalidate / revoke


def _wipe_tokens(conn: GoogleConnection) -> None:
    conn.access_token_enc = None
    conn.access_token_expires_at = None
    conn.refresh_token_enc = None


def mark_needs_reauth(db: Session, conn: GoogleConnection, reason: str) -> None:
    _wipe_tokens(conn)
    conn.status = ConnectionStatus.NEEDS_REAUTH
    conn.status_reason = reason
    db.commit()
    log.warning("connection %s needs reauth: %s", conn.id, reason)


def expire_access_token(db: Session, conn: GoogleConnection, flag: str) -> None:
    """Force the next call through a refresh, which re-asks Google if the grant is still alive."""
    conn.access_token_enc = None
    conn.access_token_expires_at = None
    conn.security_flag = flag
    db.commit()


def get_owned_connection(db: Session, user_id: str, connection_id: str) -> GoogleConnection:
    conn = db.get(GoogleConnection, connection_id)
    if conn is None or conn.user_id != user_id:
        raise ConnectionNotFound("No such connection.")
    return conn


def disconnect(db: Session, conn: GoogleConnection) -> GoogleConnection:
    """User-initiated disconnect. Revoke at Google first, then forget locally."""
    cipher = get_cipher()
    token = None
    if conn.refresh_token_enc:
        token = cipher.decrypt(conn.refresh_token_enc, conn.aad("refresh"))
    elif conn.access_token_enc:
        token = cipher.decrypt(conn.access_token_enc, conn.aad("access"))

    if token:
        try:
            google_oauth.revoke_token(token)
        except google_oauth.OAuthError as exc:
            # Stop using the grant right away, but keep the refresh token
            # (encrypted) so the revoke can be retried. Deleting it now would
            # leave a live grant at Google that we could never revoke.
            conn.access_token_enc = None
            conn.access_token_expires_at = None
            conn.status = ConnectionStatus.REVOKE_PENDING
            conn.status_reason = f"revoke failed: {exc.error}"
            db.commit()
            return conn

    _wipe_tokens(conn)
    conn.status = ConnectionStatus.REVOKED
    conn.status_reason = "disconnected by user"
    db.commit()
    return conn
