from datetime import datetime

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PF-Jira Sync"
    DEBUG: bool = False

    # Paths
    BASE_DIR: str = "."
    SQLITE_DB_PATH: str = "data/integration.db"

    # Secrets
    PF_API_KEY: str
    JIRA_AUTH: str
    JIRA_BASE_URL: str

    # Auth
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    SECRET_KEY: str  # For session signing
    INITIAL_ADMIN_EMAIL: str  # once admin - always admin

    # Infrastructure
    REDIS_URL: str = "redis://redis:6379/0"
    SEQ_URL: str = "http://seq:5341"
    SEQ_API_KEY: str | None = None
    PF_DEFAULT_JIRA_PROJECT: str = "HR"
    PF_URL: str | None = None
    JIRA_WEBHOOK_SECRET: str | None = None

    # --- Alerting & Telemetry ---
    SLACK_WEBHOOK_URL: str | None = None
    TELEGRAM_BOT_TOKEN: str | None = None
    TELEGRAM_CHAT_ID: str | None = None

    # Thresholds for the automated health checks
    ALERT_MEM_THRESHOLD_PCT: float = 90.0
    ALERT_DISK_THRESHOLD_PCT: float = 90.0
    ALERT_QUEUE_DEPTH_THRESHOLD: int = 500

    model_config = SettingsConfigDict(env_file="secrets/.env", env_file_encoding="utf-8", extra="ignore")

    # Sync Threshold
    PF_SYNC_CREATED_AFTER: datetime | None = None


settings = Settings()
