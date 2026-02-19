import logging
import os
import pathlib

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def create_structure(base_path: str = ".") -> None:
    """Scaffolds the project directory structure and core configuration files."""

    # Define directory layout
    directories = [
        "data",
        "docker",
        "secrets",
        "src/app",
        "src/config",
        "src/core",
        "src/domain/sync",
        "src/domain/webhooks",
        "src/domain/users",
        "src/static/css",
        "src/static/js",
        "src/templates/components",
        "tests",
    ]

    # Create directories
    for dir_path in directories:
        full_path = os.path.join(base_path, dir_path)
        os.makedirs(full_path, exist_ok=True)
        # Create empty __init__.py in python packages
        if "src" in dir_path or "tests" in dir_path:
            init_file = os.path.join(full_path, "__init__.py")
            pathlib.Path(init_file).touch()

    # 1. pyproject.toml (Modern UV/Ruff Config)
    pyproject_content = """[project]
name = "pf-jira-sync"
version = "0.1.0"
description = "Middleware for PeopleForce to Jira Synchronization"
requires-python = ">=3.11"
dependencies = [
    "fastapi[all]",
    "uvicorn[standard]",
    "sqlmodel",
    "pydantic-settings",
    "httpx",
    "arq",
    "redis",
    "loguru",
    "authlib",
    "itsdangerous",
    "jinja2",
    "python-multipart",
]

[dependency-groups]
dev = [
    "ruff",
    "pytest",
    "pytest-asyncio",
    "types-redis",
    "types-requests",
]

[tool.ruff]
line-length = 100
target-version = "py311"
select = ["E", "F", "I", "B", "UP", "PL", "RUF"]
ignore = []

[tool.ruff.format]
quote-style = "double"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
"""
    write_file(os.path.join(base_path, "pyproject.toml"), pyproject_content)

    # 2. Docker Compose (App + Redis + Seq)
    compose_content = """services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile
    container_name: pf_sync_app
    env_file: ./secrets/.env
    volumes:
      - ./src:/app/src
      - ./data:/app/data
    ports:
      - "8000:8000"
    depends_on:
      - redis
      - seq
    command: uvicorn src.app.main:app --host 0.0.0.0 --port 8000 --reload

  redis:
    image: redis:alpine
    container_name: pf_sync_redis
    volumes:
      - redis_data:/data
    restart: unless-stopped

  seq:
    image: datalust/seq:latest
    container_name: pf_sync_seq
    environment:
      - ACCEPT_EULA=Y
    ports:
      - "5341:80"
    volumes:
      - seq_data:/data
    restart: unless-stopped

  # Optional: Cloudflare Tunnel
  # tunnel:
  #   image: cloudflare/cloudflared
  #   command: tunnel run pf-jira-sync
  #   environment:
  #     - TUNNEL_TOKEN=${TUNNEL_TOKEN}

volumes:
  redis_data:
  seq_data:
"""
    write_file(os.path.join(base_path, "compose.yml"), compose_content)

    # 3. Dockerfile
    dockerfile_content = """FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install UV for fast package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --frozen --no-install-project

# Copy application code
COPY src ./src

# Create data dir
RUN mkdir -p data

# Environment setup
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"

CMD ["uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
"""
    write_file(os.path.join(base_path, "docker/Dockerfile"), dockerfile_content)

    # 4. Settings (src/config/settings.py)
    settings_content = """from typing import Optional
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
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    SECRET_KEY: str # For session signing

    # Infrastructure
    REDIS_URL: str = "redis://redis:6379/0"
    SEQ_URL: str = "http://seq:5341"

    model_config = SettingsConfigDict(
        env_file="secrets/.env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
"""
    write_file(os.path.join(base_path, "src/config/settings.py"), settings_content)

    # 5. Database Core (src/core/database.py)
    db_content = """from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from src.config.settings import settings

# Construct Async SQLite URL
DATABASE_URL = f"sqlite+aiosqlite:///{settings.SQLITE_DB_PATH}"

engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False} # Needed for SQLite
)

# Enable WAL Mode on Connect
@org.event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

async_session_maker = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session
"""
    # Fix imports in the string above for the file write
    db_content = "import sqlalchemy.event as org\n" + db_content
    write_file(os.path.join(base_path, "src/core/database.py"), db_content)

    # 6. Gitignore
    gitignore_content = """
__pycache__/
*.pyc
.env
secrets/
data/
.venv/
.idea/
.vscode/
dist/
*.egg-info/
"""
    write_file(os.path.join(base_path, ".gitignore"), gitignore_content)

    # 7. Placeholder for secrets/.env
    write_file(
        os.path.join(base_path, "secrets/.env"),
        "# PF_API_KEY=...\n# JIRA_AUTH=...\nSECRET_KEY=changeme",
    )

    logger.info("Project scaffolding complete.")


def write_file(path: str, content: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Created: {path}")
    except Exception as e:
        logger.error(f"Failed to create {path}: {e}")


if __name__ == "__main__":
    create_structure()
