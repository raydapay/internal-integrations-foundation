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

    # Infrastructure
    REDIS_URL: str = "redis://redis:6379/0"
    SEQ_URL: str = "http://seq:5341"
    SEQ_API_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file="secrets/.env", env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
