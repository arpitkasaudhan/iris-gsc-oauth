"""Search Console + Indexing API calls made with a user's delegated token."""

from urllib.parse import quote, urlsplit

import httpx
from sqlalchemy.orm import Session

from app import token_service
from app.config import get_settings
from app.errors import GoogleUpstreamError, NotPropertyOwner, QuotaExceeded, ReauthRequired, ScopeNotGranted
from app.google_oauth import SCOPE_GSC_READONLY, SCOPE_INDEXING
from app.models import GoogleConnection

SITES_URL = "https://www.googleapis.com/webmasters/v3/sites"
INDEXING_PUBLISH_URL = "https://indexing.googleapis.com/v3/urlNotifications:publish"
INDEXING_METADATA_URL = "https://indexing.googleapis.com/v3/urlNotifications/metadata"
URL_INSPECTION_URL = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect"


class GoogleAPIError(Exception):
    def __init__(self, status: int, message: str, reason: str | None = None):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message
        self.reason = reason


def require_scope(conn: GoogleConnection, scope: str) -> None:
    # With granular consent the user can untick individual scopes, so a
    # successful connect does not imply every scope was granted.
    if scope not in conn.scopes:
        raise ScopeNotGranted(
            f"The user did not grant {scope}. Reconnect and tick it on the consent screen.",
            reauth_url="/oauth/google/connect",
        )


def _raise_for_google(resp: httpx.Response) -> None:
    try:
        err = resp.json().get("error", {})
    except ValueError:
        err = {}
    message = err.get("message") or resp.text[:300]
    reason = (err.get("errors") or [{}])[0].get("reason") or err.get("status")
    if resp.status_code == 429:
        raise QuotaExceeded(message, retry_after=resp.headers.get("Retry-After"))
    raise GoogleAPIError(resp.status_code, message, reason)


def call_google(db: Session, conn: GoogleConnection, method: str, url: str, **kwargs) -> dict:
    """Authenticated call with one transparent retry on 401.

    A 401 means the access token died early (revoked, or clock skew). We
    refresh once and retry. If the refresh itself fails with invalid_grant,
    token_service flips the connection to needs_reauth.
    """
    token = token_service.get_access_token(db, conn)
    with httpx.Client(timeout=get_settings().http_timeout_seconds) as client:
        for attempt in range(2):
            try:
                resp = client.request(method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs)
            except httpx.TransportError as exc:
                raise GoogleUpstreamError(f"Network error calling Google: {exc}") from exc
            if resp.status_code == 401 and attempt == 0:
                token = token_service.get_access_token(db, conn, stale=token)
                continue
            if resp.status_code == 401:
                token_service.mark_needs_reauth(db, conn, "401 after a fresh refresh")
                raise ReauthRequired("Google rejected a freshly refreshed token.", conn.id)
            if resp.status_code >= 500:
                raise GoogleUpstreamError(f"Google returned {resp.status_code}.")
            if resp.status_code >= 400:
                _raise_for_google(resp)
            return resp.json() if resp.content else {}
    raise AssertionError("unreachable")


# ---------------------------------------------------------------- properties


def list_sites(db: Session, conn: GoogleConnection) -> list[dict]:
    require_scope(conn, SCOPE_GSC_READONLY)
    return call_google(db, conn, "GET", SITES_URL).get("siteEntry", [])


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def match_property(sites: list[dict], page_url: str) -> dict | None:
    """Pick the most specific Search Console property covering ``page_url``.

    Two property kinds exist:
      * URL-prefix: ``https://www.example.com/blog/`` covers URLs starting with it.
      * Domain:     ``sc-domain:example.com`` covers every scheme and subdomain.
    Owner properties win over non-owner ones, then longer prefixes win.
    """
    host = _host(page_url)
    candidates: list[tuple[int, int, dict]] = []
    for site in sites:
        site_url = site.get("siteUrl", "")
        if site_url.startswith("sc-domain:"):
            domain = site_url.removeprefix("sc-domain:").lower()
            if host == domain or host.endswith("." + domain):
                specificity = len(domain)
            else:
                continue
        elif page_url.startswith(site_url):
            specificity = 1000 + len(site_url)  # a prefix is narrower than a domain
        else:
            continue
        is_owner = 1 if site.get("permissionLevel") == "siteOwner" else 0
        candidates.append((is_owner, specificity, site))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    return candidates[0][2]


def resolve_owned_property(db: Session, conn: GoogleConnection, page_url: str) -> dict:
    site = match_property(list_sites(db, conn), page_url)
    if site is None:
        raise NotPropertyOwner(
            f"{conn.google_email} has no Search Console property covering {page_url}.",
            connection_id=conn.id,
        )
    if site.get("permissionLevel") != "siteOwner":
        # The Indexing API only accepts calls from VERIFIED OWNERS. Full users
        # get a 403 "Permission denied. Failed to verify the URL ownership."
        raise NotPropertyOwner(
            f"{conn.google_email} is {site.get('permissionLevel')} on {site['siteUrl']}; "
            "the Indexing API requires siteOwner.",
            connection_id=conn.id,
            site_url=site["siteUrl"],
        )
    return site


# ---------------------------------------------------------------- indexing


def publish_url_notification(db: Session, conn: GoogleConnection, page_url: str, notification_type: str) -> dict:
    require_scope(conn, SCOPE_INDEXING)
    return call_google(db, conn, "POST", INDEXING_PUBLISH_URL, json={"url": page_url, "type": notification_type})


def get_notification_metadata(db: Session, conn: GoogleConnection, page_url: str) -> dict:
    require_scope(conn, SCOPE_INDEXING)
    return call_google(db, conn, "GET", f"{INDEXING_METADATA_URL}?url={quote(page_url, safe='')}")


def inspect_url(db: Session, conn: GoogleConnection, page_url: str, site_url: str) -> dict:
    require_scope(conn, SCOPE_GSC_READONLY)
    return call_google(
        db, conn, "POST", URL_INSPECTION_URL, json={"inspectionUrl": page_url, "siteUrl": site_url}
    )
