# OAuth Whiteboard: Google Search Console, end to end

**Question:** build a FastAPI utility with a complete OAuth flow for Google Search Console, and walk through every step until we can request indexing of a page on the user's behalf, on demand. Cover token storage, refresh, revocation, and what happens when the user changes their Google password.

**Short answer:** the user connects once through an offline, PKCE-protected authorization code flow. We keep only an AES-256-GCM encrypted refresh token, mint short-lived access tokens on demand, and call the Indexing API as that user, but only after checking that the account is a **verified owner** of the Search Console property covering the URL. Every failure path ends in one of two states: *retry later* (Google or the network had a hiccup) or *needs reauth* (the grant is gone and only the user can fix it). A password change is just one of several ways to reach the second state, and the code does not need a special case for it.

Code references point into this repo. Diagrams are in [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 0. One-time setup (Google Cloud Console)

1. Create a project and enable two APIs: **Google Search Console API** (sites list, URL inspection) and **Web Search Indexing API** (the indexing call itself).
2. Configure the **OAuth consent screen** (External), add the scopes below, and add test users while in Testing.
3. Create an **OAuth client ID** of type *Web application* and register the exact redirect URI, for example `https://app.example.com/oauth/google/callback`. Google matches it byte for byte.
4. Scopes, chosen for least privilege:

| Scope | Why |
|---|---|
| `openid`, `email` | Know *which* Google account granted access (`sub`), so a reconnect updates the same row |
| `https://www.googleapis.com/auth/webmasters.readonly` | List properties and the user's permission level on each, URL inspection |
| `https://www.googleapis.com/auth/indexing` | `urlNotifications:publish` and `metadata` |

We do not ask for full `webmasters` because nothing here writes to Search Console.

**Production note:** while the consent screen is in *Testing*, Google expires refresh tokens after **7 days**. That alone breaks "on demand" indexing, so the app must be published (and verified by Google for any sensitive scopes) before real users connect.

## 1. Connect: send the user to Google

`GET /oauth/google/connect` ([`token_service.start_connect`](../app/token_service.py), [`google_oauth.build_authorization_url`](../app/google_oauth.py))

The user is already logged in to *our* product. We generate:

* **`state`**: 32 random bytes. We store only `sha256(state)`, bound to the current user id, with a 10 minute expiry.
* **PKCE**: a random `code_verifier` (stored encrypted next to the state) and `code_challenge = BASE64URL(SHA256(verifier))`.

Then we redirect to `https://accounts.google.com/o/oauth2/v2/auth` with:

| Parameter | Value | Why |
|---|---|---|
| `response_type` | `code` | Authorization code flow. Tokens never touch the browser |
| `access_type` | `offline` | We need a **refresh token** to act while the user is away |
| `prompt` | `consent` | Google only returns a refresh token on the *first* consent. Forcing consent guarantees one on every reconnect, which is how a user recovers from a dead grant |
| `include_granted_scopes` | `true` | Incremental auth if we add scopes later |
| `state`, `code_challenge`, `code_challenge_method=S256` | | CSRF protection and code-interception protection |
| `login_hint` (optional) | email | Pre-selects the right Google account for agencies with several |

## 2. Callback: turn the code into tokens

`GET /oauth/google/callback?code&state` ([`token_service.complete_connect`](../app/token_service.py))

1. `?error=access_denied` means the user clicked Cancel. Return a clear error.
2. **Validate `state`**: it must exist, be unused, be unexpired, and belong to the **same logged-in user**. It is burned on first use. The user binding stops login CSRF, where an attacker gets a victim's browser to complete the attacker's consent and silently link the wrong Google account.
3. **Exchange the code** at `POST https://oauth2.googleapis.com/token` with `grant_type=authorization_code`, the `code_verifier`, client id/secret and the same `redirect_uri`. This is server to server, so the secret never reaches the browser.
4. **Read the `id_token`** to get `sub` (Google's stable account id; email can change) and `email`. Because the token came straight from Google's token endpoint over TLS, Google allows skipping signature verification. We still check `iss`, `aud` and `exp`.
5. **Check the granted scopes.** With granular consent the user can untick individual scopes. The `scope` field in the response is the truth. We store it and report anything missing (`missing_scopes`), and the indexing endpoint returns `403 scope_not_granted` with a reconnect link instead of a confusing Google error.
6. **Upsert** the connection on `(user_id, google_sub)`, so reconnecting never creates duplicates, and one product user can link several Google accounts (agency use case).
7. If no refresh token came back, fail now rather than silently breaking an hour later.

## 3. Token storage

Table `google_connections` ([`models.py`](../app/models.py)):

| Column | Notes |
|---|---|
| `user_id`, `google_sub`, `google_email` | Unique on `(user_id, google_sub)` |
| `refresh_token_enc` | The only long-lived secret. AES-256-GCM |
| `access_token_enc`, `access_token_expires_at` | Cached so we do not refresh on every call |
| `granted_scopes` | What the user actually granted |
| `status`, `status_reason`, `security_flag` | `active`, `needs_reauth`, `revoked`, `revoke_pending` |

Encryption ([`crypto.py`](../app/crypto.py)):

* **AES-256-GCM** with a random 96-bit nonce per write. Format `v1.<kid>.<nonce+ciphertext+tag>`.
* **AAD binds each ciphertext to its row** (`conn:<id>:refresh`). Copying an encrypted token into another user's row makes decryption fail instead of handing that user someone else's Google access.
* **Key ring with key ids**, so rotation is "prepend a new key". Old rows still decrypt and are re-encrypted with the new key the next time they are refreshed.
* Tokens are never logged and never returned by any endpoint. `GET /connections` shows status and expiry only.
* In production the key ring would come from a KMS (envelope encryption: KMS-wrapped data keys), not an env var. Everything else stays the same.

## 4. Requesting indexing on demand

`POST /gsc/index {"url": "...", "type": "URL_UPDATED" | "URL_DELETED"}` ([`routers/gsc.py`](../app/routers/gsc.py), [`gsc_client.py`](../app/gsc_client.py))

1. **Get a valid access token** (section 5).
2. **Find the property and check ownership.** `GET https://www.googleapis.com/webmasters/v3/sites` returns each property with a `permissionLevel`. We match the URL to the most specific property: URL-prefix properties (`https://www.example.com/blog/`) by prefix, domain properties (`sc-domain:example.com`) by host and subdomain. The Indexing API only accepts calls from a **verified owner** (`siteOwner`). A `siteFullUser` gets `403 Permission denied. Failed to verify the URL ownership`, so we check first and return an actionable message. If the user linked several Google accounts and did not pick one, we use the one that owns the property.
3. **Publish**: `POST https://indexing.googleapis.com/v3/urlNotifications:publish` with `{"url": ..., "type": "URL_UPDATED"}` and `Authorization: Bearer <access token>`. Google answers with `urlNotificationMetadata.latestUpdate.notifyTime`.
4. **Audit**: every attempt, success or failure, is written to `index_requests` (`GET /gsc/index/history`).
5. **Follow up**: `GET /gsc/index/status?url=` (Indexing API metadata) and `POST /gsc/inspect` (URL Inspection API, Google's actual view of the page).

Honest caveats an integration engineer should raise with the product team:

* Google documents the Indexing API for pages with **`JobPosting` or `BroadcastEvent` (in a `VideoObject`)** structured data. It accepts other URLs, but Google may ignore them and does not promise crawling or indexing for anything.
* The **"Request indexing" button in the Search Console UI has no public API**. The Indexing API is the closest supported equivalent. For general pages the supported signal is a sitemap (`sitemaps.submit`, which needs the full `webmasters` scope).
* Default quota is **200 publish requests per day per Cloud project**, shared by all users. `429` is surfaced as `429 google_quota_exceeded`. At scale this endpoint should enqueue and a worker should drain the queue within quota.

## 5. Refresh

[`token_service.get_access_token`](../app/token_service.py)

* **Proactive**: refresh when the cached token has less than 120 s left. Google access tokens live about one hour.
* **Single flight**: a per-connection lock, then re-read the row, so ten concurrent requests cause one refresh, not ten. With several workers the same pattern uses `SELECT ... FOR UPDATE` or a Redis lock.
* **Reactive**: on a `401` from Google we refresh once and retry once. The `stale` argument makes sure that if another request already refreshed, we reuse its token instead of refreshing again.
* **Rotation**: if Google returns a new `refresh_token`, it replaces the old one.

Error handling is the important part:

| Google says | Meaning | What we do |
|---|---|---|
| `200` | | Store new access token, keep going |
| `400 invalid_grant` | Grant is dead: revoked, expired, password change on Gmail-scoped grant, 6 months unused, Testing-mode 7 days, admin session policy, over the 100 refresh tokens limit | **Terminal.** Wipe tokens, `status=needs_reauth`, API returns `409 google_reauth_required` with `reauth_url`. Never retried |
| `5xx`, timeout | Google or network hiccup | Retry with backoff, then `502`. **The grant is not touched.** Treating a 503 as "revoked" would log out every user during a Google incident |
| `400 invalid_client` / `unauthorized_client` | Our client secret or config is wrong | Error, page the on-call. Not the user's fault |

## 6. Revocation

There are two directions.

**The user disconnects in our product:** `DELETE /connections/{id}` ([`token_service.disconnect`](../app/token_service.py))

1. `POST https://oauth2.googleapis.com/revoke` with the **refresh token**. That kills the refresh token, every access token minted from it, and removes our app from the user's Google Account permissions page.
2. `200`, or `400 invalid_token` (already revoked): wipe both tokens, `status=revoked`.
3. Google unreachable: stop using the grant immediately (access token wiped) but keep the encrypted refresh token with `status=revoke_pending` so the revoke can be retried. Deleting it here would leave a live grant at Google that we can never revoke.

**The user revokes us at Google** (myaccount.google.com/permissions, or a Workspace admin removes the app). Nothing calls us by default. We find out either:

* lazily, from `invalid_grant` on the next refresh (section 5), or
* immediately, through **Cross-Account Protection (RISC)**: Google pushes a signed Security Event Token to `POST /risc/events` ([`risc.py`](../app/risc.py)). We verify it against Google's JWKS (issuer, audience = our client id), de-duplicate on `jti`, and on `tokens-revoked` wipe the grant right away.

## 7. What happens when the user changes their Google password

This is the trick question, so precisely:

1. **Access tokens** already issued are short-lived bearer tokens. We never rely on them for more than an hour either way.
2. **Refresh tokens:** Google's documented rule is that a password change revokes refresh tokens **only when the grant includes Gmail scopes**. Our scopes (`webmasters.readonly`, `indexing`, `openid`, `email`) are not Gmail scopes, so **in the normal case the grant survives and indexing keeps working**. That is the correct behavior for a background integration: a routine password rotation should not break the customer's automation.
3. **But a password change is often not routine.** If it happens during account recovery or after a hijack, if the user picks "sign out of all devices", or if a Workspace admin enforces re-authentication, Google can and does revoke grants. The next refresh then returns `invalid_grant`.
4. **How the utility handles both cases without special-casing "password":**
   * **Reactive (always on):** `invalid_grant` puts the connection in `needs_reauth`, wipes the tokens, and every call returns `409` with a reconnect link. No retry storms against Google, no silent failures.
   * **Proactive (RISC, optional):** Google pushes the event within minutes.
     * `sessions-revoked` (typical of a password reset with sign-out everywhere): we expire the cached access token so the next call must refresh. That refresh is the proof: if Google killed the grant, we hit `invalid_grant` and move to `needs_reauth`; if not, we carry on. We neither panic nor ignore it.
     * `tokens-revoked`, or `account-disabled` with reason `hijacking`: wipe immediately.
     * `account-credential-change-required`: flag the connection so the product can warn the user.
   * **Recovery:** the user clicks Reconnect, goes through section 1 again with `prompt=consent`, gets a new refresh token, and the same row (matched on `google_sub`) goes back to `active`.
5. **Product choice:** if iris wants "password change means stop acting on my behalf" as a security policy, flip the `sessions-revoked` handler from *expire access token* to *wipe grant*. It is a one-line change because the state machine already exists.

## 8. Production hardening (beyond the take-home)

* Real auth instead of `/dev/login`; `https_only` session cookies (already automatic when the redirect URI is https).
* KMS-backed key ring; scheduled re-encryption job for rows on old key ids.
* Distributed refresh lock (Postgres row lock or Redis) for multiple workers.
* Indexing requests through a queue with a per-project daily budget, and a per-user fair share.
* Refresh tokens unused for **6 months** expire. Tenants that rarely index should be refreshed by a monthly job, or shown a "reconnect" nudge.
* Google allows **100 live refresh tokens per Google account per client**; older ones are silently invalidated. Since every reconnect mints a new one, we always overwrite and never keep extras.
* Metrics and alerts: refresh success rate, `invalid_grant` rate per hour (a spike means a config or Google-side issue, not 500 users revoking at once), quota usage, RISC events received.
* Register the RISC receiver with Google (`risc.googleapis.com/v1beta/stream:update`, authenticated as a service account with the RISC Configuration Admin role).

## 9. How to verify it

```bash
pytest   # 43 tests, Google fully mocked with respx
```

The tests walk the same story as this document: the PKCE redirect, state replay, state from another user, partial consent, encrypted storage, transparent refresh, `invalid_grant` leading to `needs_reauth`, Google 503 not dropping the grant, 401 refresh-and-retry, siteFullUser rejected, multi-account owner selection, quota 429, revoke (ok, already revoked, Google down then retry), RISC events (signature, audience, idempotency, each event type) and key rotation.
