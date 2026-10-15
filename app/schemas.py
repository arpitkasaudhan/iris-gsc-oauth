from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

from app.models import ConnectionStatus, GoogleConnection


class ConnectionOut(BaseModel):
    id: str
    google_email: str | None
    status: ConnectionStatus
    status_reason: str | None
    security_flag: str | None
    granted_scopes: list[str]
    access_token_expires_at: datetime | None
    last_refreshed_at: datetime | None
    created_at: datetime

    @classmethod
    def of(cls, conn: GoogleConnection) -> "ConnectionOut":
        return cls(
            id=conn.id,
            google_email=conn.google_email,
            status=conn.status,
            status_reason=conn.status_reason,
            security_flag=conn.security_flag,
            granted_scopes=sorted(conn.scopes),
            access_token_expires_at=conn.access_token_expires_at,
            last_refreshed_at=conn.last_refreshed_at,
            created_at=conn.created_at,
        )


class IndexRequestIn(BaseModel):
    url: HttpUrl
    type: Literal["URL_UPDATED", "URL_DELETED"] = "URL_UPDATED"
    connection_id: str | None = Field(
        default=None, description="Optional. If omitted, the user's connection that owns the property is used."
    )


class IndexRequestOut(BaseModel):
    request_id: str
    url: str
    type: str
    site_url: str
    connection_id: str
    google_email: str | None
    notify_time: str | None
    google_response: dict


class InspectIn(BaseModel):
    url: HttpUrl
    connection_id: str | None = None
