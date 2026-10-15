# Architecture and flow diagrams

## Components

```mermaid
flowchart LR
    U["User's browser"] -->|"1. Connect Google"| API
    U <-->|"2. Consent screen"| GA["accounts.google.com"]
    GA -->|"3. Redirect with code + state"| API

    subgraph API["FastAPI utility"]
        R1["/oauth/google/*<br/>connect, callback"]
        R2["/connections<br/>list, refresh, disconnect"]
        R3["/gsc/*<br/>sites, index, status, inspect"]
        R4["/risc/events<br/>security events"]
        TS["token_service<br/>state, PKCE, refresh, revoke"]
        GC["gsc_client<br/>property match, 401 retry"]
        CR["crypto<br/>AES-256-GCM key ring"]
        R1 --> TS
        R2 --> TS
        R3 --> GC --> TS
        R4 --> TS
        TS --> CR
    end

    TS <-->|"code exchange, refresh, revoke"| GT["oauth2.googleapis.com"]
    GC -->|"sites list"| WM["Search Console API"]
    GC -->|"urlNotifications:publish"| IX["Indexing API"]
    GC -->|"urlInspection"| SC["URL Inspection API"]
    G2["Google RISC"] -->|"signed SET"| R4
    API --- DB[("DB<br/>oauth_states<br/>google_connections<br/>index_requests<br/>security_events")]
```

## Connect (authorization code + PKCE)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as FastAPI
    participant DB
    participant Google as accounts.google.com
    participant Token as oauth2.googleapis.com/token

    User->>App: GET /oauth/google/connect (logged-in session)
    App->>App: state = random 32B, verifier = random, challenge = S256(verifier)
    App->>DB: save sha256(state), user_id, enc(verifier), expires +10m
    App-->>User: 302 to Google (access_type=offline, prompt=consent, scopes, state, challenge)
    User->>Google: sign in + consent (may untick scopes)
    Google-->>User: 302 /oauth/google/callback?code&state
    User->>App: GET /callback?code&state
    App->>DB: state exists, unused, unexpired, same user? burn it
    App->>Token: code + code_verifier + client secret
    Token-->>App: access_token, refresh_token, expires_in, scope, id_token
    App->>App: check id_token iss, aud, exp. Read sub, email
    App->>DB: upsert (user_id, sub): enc(refresh), enc(access), expiry, granted scopes
    App-->>User: connected + missing_scopes
```

## Request indexing, with transparent refresh

```mermaid
sequenceDiagram
    autonumber
    participant Client as Caller
    participant App as FastAPI
    participant DB
    participant Token as Google token endpoint
    participant GSC as Search Console API
    participant IDX as Indexing API

    Client->>App: POST /gsc/index {url, type}
    App->>DB: load active connections
    alt access token expires within 120s
        App->>Token: grant_type=refresh_token (single flight per connection)
        alt 200
            Token-->>App: new access token (maybe new refresh token)
            App->>DB: store encrypted
        else 400 invalid_grant
            App->>DB: wipe tokens, status = needs_reauth
            App-->>Client: 409 google_reauth_required + reauth_url
        else 5xx / timeout
            App-->>Client: 502, grant untouched
        end
    end
    App->>GSC: GET /sites
    GSC-->>App: properties + permissionLevel
    App->>App: most specific property for url, must be siteOwner
    App->>IDX: POST urlNotifications:publish
    alt 401
        App->>Token: refresh once
        App->>IDX: retry once
    end
    IDX-->>App: urlNotificationMetadata (notifyTime)
    App->>DB: audit row in index_requests
    App-->>Client: 200 submitted
```

## Connection state machine

```mermaid
stateDiagram-v2
    [*] --> active: callback succeeds
    active --> active: refresh ok / 5xx (retry later)
    active --> needs_reauth: invalid_grant on refresh
    active --> needs_reauth: RISC tokens-revoked or account hijacked
    active --> active: RISC sessions-revoked (access token expired, refresh decides)
    active --> revoked: user disconnects, Google revoke ok
    active --> revoke_pending: user disconnects, Google revoke fails
    revoke_pending --> revoked: disconnect retried
    needs_reauth --> active: user reconnects (prompt=consent)
    revoked --> active: user reconnects
```

## Password change decision tree

```mermaid
flowchart TD
    P["User changes Google password"] --> Q{"Grant has Gmail scopes?"}
    Q -->|"yes"| R["Google revokes refresh token"]
    Q -->|"no (our case)"| S{"Recovery / hijack / sign out everywhere / admin policy?"}
    S -->|"no"| K["Grant survives. Indexing keeps working"]
    S -->|"yes"| R
    R --> E1["RISC tokens-revoked pushed (if registered)"]
    R --> E2["Next refresh returns invalid_grant"]
    E1 --> N["status = needs_reauth, tokens wiped"]
    E2 --> N
    S -->|"sessions-revoked event only"| X["Expire cached access token"] --> F{"Refresh succeeds?"}
    F -->|"yes"| K
    F -->|"no, invalid_grant"| N
    N --> UI["API returns 409 + reauth_url. User reconnects, same row goes active"]
```
