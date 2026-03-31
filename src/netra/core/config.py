"""Application configuration via Pydantic Settings."""
import secrets
import warnings
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="NETRA_",
    )

    # ── App ──
    app_name: str = "NETRA"
    app_version: str = "1.0.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # ── Database ──
    database_url: str = "sqlite+aiosqlite:///./netra.db"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # ── API ──
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_cors_origins: list[str] = Field(default=["http://localhost:5173"])
    api_rate_limit: str = "100/minute"

    # ── Auth ──
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    csrf_secret_key: str = ""
    cookie_secure: bool = False  # Set to True in production with HTTPS
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    @model_validator(mode="after")
    def validate_jwt_secret(self) -> "Settings":
        """Ensure JWT secret is set properly.

        In production, require an explicit secret key.
        In development, generate a random one if not provided.
        """
        insecure_defaults = {"", "CHANGE-ME-IN-PRODUCTION", "change-me-in-production", "secret"}
        if self.jwt_secret_key in insecure_defaults:
            if self.environment == "production":
                raise ValueError(
                    "NETRA_JWT_SECRET_KEY must be set to a strong secret in "
                    "production. Generate one with: "
                    "python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            # Auto-generate for development only
            self.jwt_secret_key = secrets.token_urlsafe(64)
            warnings.warn(
                "JWT secret not set — auto-generated for development. "
                "Set NETRA_JWT_SECRET_KEY for persistent sessions.",
                UserWarning,
                stacklevel=2,
            )

        # Auto-generate CSRF secret if not provided
        if not self.csrf_secret_key:
            self.csrf_secret_key = secrets.token_urlsafe(64)

        return self

    # ── AI ──
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    anthropic_skeptic_model: str = "claude-haiku-4-5-20251001"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ai_token_budget_per_scan: int = 50000
    ai_provider: Literal["anthropic", "ollama", "none"] = "none"

    # ── Celery ──
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # ── Notifications ──
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    notification_email_from: str = ""
    notification_email_to: list[str] = Field(default=[])

    # ── Scanning ──
    default_scan_profile: str = "standard"
    max_concurrent_scans: int = 3
    scan_timeout_hours: int = 12
    tools_dir: Path = Path.home() / ".netra" / "tools"
    wordlists_dir: Path = Path.home() / ".netra" / "wordlists"
    shodan_api_key: str = ""

    # ── Reports ──
    reports_dir: Path = Path.home() / ".netra" / "reports"
    evidence_dir: Path = Path.home() / ".netra" / "evidence"


settings = Settings()
