from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str = "http://localhost:8000/oauth/google/callback"

    token_encryption_keys: str
    session_secret: str
    database_url: str = "sqlite:///./gsc_oauth.db"

    enable_dev_login: bool = False
    risc_enabled: bool = False

    oauth_state_ttl_seconds: int = 600
    # Refresh this many seconds before Google's stated expiry so a token never dies mid-request.
    access_token_skew_seconds: int = 120
    http_timeout_seconds: float = 10.0

    # Google's Indexing API quota is per Cloud project (default 200 publish
    # calls/day, reset at midnight Pacific). We track it locally so we refuse
    # before burning a call, and can cap any single user's share of it.
    indexing_daily_quota: int = 200
    indexing_daily_quota_per_user: int = 0  # 0 = no per-user cap
    batch_max_urls: int = 100
    sites_cache_ttl_seconds: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
