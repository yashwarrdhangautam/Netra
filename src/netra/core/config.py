"""Application configuration via Pydantic Settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field
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
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # ── Database ──
    database_url: str = "sqlite+aiosqlite:///./netra.db"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10
    # Celery workers call asyncio.run() several times per task. A pooled asyncpg connection
    # is bound to the loop that created it, so workers open a connection per checkout instead.
    db_null_pool: bool = False

    # ── API ──
    api_host: str = "0.0.0.0"  # noqa: S104 - the API runs in a container and binds all interfaces
    api_port: int = 8000
    api_cors_origins: list[str] = Field(default=["http://localhost:5173"])
    api_rate_limit: str = "100/minute"

    # ── Auth ──
    # Compose refuses to start without NETRA_JWT_SECRET_KEY; this default is for local runs.
    jwt_secret_key: str = "CHANGE-ME-IN-PRODUCTION"  # noqa: S105
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    # Self sign-up creates viewer accounts. Off by default; admins create users in the GUI.
    allow_self_signup: bool = False

    # ── AI ──
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    anthropic_skeptic_model: str = "claude-haiku-4-5-20251001"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    agentic_orchestrator_model: str = ""
    agentic_service_analyst_model: str = ""
    agentic_security_expert_model: str = ""
    agentic_attack_path_model: str = ""
    agentic_report_synth_model: str = ""
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
    wpscan_api_token: str = ""

    # ── Reports ──
    reports_dir: Path = Path.home() / ".netra" / "reports"
    evidence_dir: Path = Path.home() / ".netra" / "evidence"
    corpus_source_hackerone: bool = True
    corpus_source_advisories: bool = True
    corpus_source_writeups: bool = True
    corpus_obey_robots: bool = True
    corpus_default_rps: float = 1.0
    corpus_source_chaos: bool = True
    corpus_source_repo_heads: bool = True
    corpus_source_bugcrowd: bool = True
    # Bug bounty module (NETRA-BB). Set NETRA_BB_ENABLED=false to run the core scanner only.
    bb_enabled: bool = True


settings = Settings()
