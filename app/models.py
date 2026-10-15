import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


class ConnectionStatus(str, enum.Enum):
    ACTIVE = "active"
    # Google rejected the refresh token (invalid_grant) or a RISC event told us
    # the grant is gone. Tokens are wiped; the user must reconnect.
    NEEDS_REAUTH = "needs_reauth"
    # User disconnected and Google confirmed the revocation.
    REVOKED = "revoked"
    # User disconnected but Google's revoke endpoint failed. We stop using the
    # token immediately and keep it only so the revoke can be retried.
    REVOKE_PENDING = "revoke_pending"


class OAuthState(Base):
    """One row per in-flight consent screen. Single use, short lived."""

    __tablename__ = "oauth_states"

    # sha256(state). The raw value only ever lives in the redirect URL.
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    code_verifier_enc: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime)


class GoogleConnection(Base):
    """A user's link to one Google account. A user may link several."""

    __tablename__ = "google_connections"
    __table_args__ = (UniqueConstraint("user_id", "google_sub"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    # Google's stable account id. Email can change, sub never does.
    google_sub: Mapped[str] = mapped_column(String(255), index=True)
    google_email: Mapped[str | None] = mapped_column(String(320))
    granted_scopes: Mapped[str] = mapped_column(Text, default="")

    refresh_token_enc: Mapped[str | None] = mapped_column(Text)
    access_token_enc: Mapped[str | None] = mapped_column(Text)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime)

    status: Mapped[ConnectionStatus] = mapped_column(
        Enum(ConnectionStatus, native_enum=False), default=ConnectionStatus.ACTIVE
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    security_flag: Mapped[str | None] = mapped_column(String(255))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    last_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime)

    def aad(self, kind: str) -> str:
        return f"conn:{self.id}:{kind}"

    @property
    def scopes(self) -> set[str]:
        return set(self.granted_scopes.split())


class IndexRequest(Base):
    """Audit log of every indexing call made on a user's behalf."""

    __tablename__ = "index_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    connection_id: Mapped[str | None] = mapped_column(ForeignKey("google_connections.id"))
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    url: Mapped[str] = mapped_column(Text)
    notification_type: Mapped[str] = mapped_column(String(32))
    site_url: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(32))
    http_status: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SecurityEvent(Base):
    """RISC events received from Google, keyed by jti for idempotency."""

    __tablename__ = "security_events"

    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(Text)
    google_sub: Mapped[str | None] = mapped_column(Text)
    action_taken: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
