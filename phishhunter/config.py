"""Runtime configuration for local, hosted and Vercel deployments."""

from __future__ import annotations

import os
import secrets

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _is_vercel_runtime() -> bool:
    """Return True when running in a Vercel deployment or under `vercel dev`."""
    return bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))


def _default_app_env() -> str:
    if _is_vercel_runtime():
        return os.getenv("VERCEL_ENV", "production")
    return "dev"


def _default_secret_key() -> str:
    # Local development keeps the documented non-production fallback.
    # On Vercel, do not fall back to a publicly known signing key. Configure
    # SECRET_KEY in Vercel for stable authentication across instances/redeploys.
    if _is_vercel_runtime():
        if not os.getenv("SECRET_KEY"):
            import warnings

            warnings.warn(
                "SECRET_KEY is not configured. A temporary process-local key is being used; "
                "configure SECRET_KEY in Vercel before enabling real accounts.",
                RuntimeWarning,
                stacklevel=2,
            )
        return secrets.token_urlsafe(48)
    return "dev-only-change-me-please-32-bytes"


def _default_database_url() -> str:
    configured = os.getenv("DATABASE_URL")
    if configured:
        return configured
    # Vercel's deployed source tree is read-only. This fallback lets a preview
    # boot for visual testing, but data in /tmp is transient and not production storage.
    if _is_vercel_runtime():
        return "sqlite:////tmp/phishhunter-demo.db"
    return "sqlite:///./data/phishhunter.db"


def _default_storage_dir() -> str:
    if _is_vercel_runtime():
        return "/tmp/phishhunter-storage"
    return "./data/storage"


def _default_public_base_url() -> str:
    host = os.getenv("VERCEL_PROJECT_PRODUCTION_URL") or os.getenv("VERCEL_URL")
    if host:
        host = host.strip().rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host
    return "http://127.0.0.1:8000"


def _default_admin_base_url() -> str:
    return f"{_default_public_base_url().rstrip('/')}/admin"


def _default_cookie_secure() -> bool:
    return _is_vercel_runtime()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Phish-Hunter-k4"
    app_env: str = Field(default_factory=_default_app_env)
    host: str = "127.0.0.1"
    port: int = 8000
    secret_key: str = Field(default_factory=_default_secret_key)
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    database_url: str = Field(default_factory=_default_database_url)
    storage_dir: str = Field(default_factory=_default_storage_dir)
    max_upload_mb: int = 25
    max_email_attachment_mb: int = 8
    max_nested_archive_depth: int = 3
    max_archive_files: int = 2000
    public_base_url: str = Field(default_factory=_default_public_base_url)
    admin_base_url: str = Field(default_factory=_default_admin_base_url)
    allowed_hosts: str = "127.0.0.1,localhost"
    verify_dns: bool = True
    fetch_timeout_seconds: int = 12
    max_redirects: int = 8
    cookie_secure: bool = Field(default_factory=_default_cookie_secure)
    csrf_cookie_name: str = "phishhunter_csrf"
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 120
    auth_rate_limit_max_requests: int = 12
    analysis_rate_limit_max_requests: int = 24
    enable_external_ti: bool = False
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    abuseipdb_api_key: str = ""
    hibp_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    dnsdumpster_api_key: str = ""
    wappalyzer_api_key: str = ""
    linkedin_access_token: str = ""
    linkedin_organization_id: str = ""
    linkedin_version: str = "202610"
    ipinfo_api_key: str = ""
    securitytrails_api_key: str = ""
    domaintools_api_key: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"
    sandbox_enabled: bool = False
    sandbox_backend: str = "disabled"
    sandbox_endpoint: str = ""
    trusted_proxy_count: int = 0
    analysis_retention_days: int = 30
    max_result_json_bytes: int = 5_000_000


settings = Settings()
