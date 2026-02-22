import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# Ensure canonical imports are resolved
import src.domain.users.models  # noqa: F401
from src.config.settings import settings
from src.domain.pf_jira.models import DomainConfig


class DummyLock:
    """A safe, strictly compliant async context manager to bypass Redis locks in tests."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@asynccontextmanager
async def dummy_async_context(*args, **kwargs):
    """Provides a safe, non-blocking mock for 'async with' Redis lock blocks."""
    yield None


class BaseTest(unittest.IsolatedAsyncioTestCase):
    """Base test class providing strict, ephemeral database isolation."""

    async def asyncSetUp(self) -> None:
        """Bootstraps a pure in-memory database and intercepts worker connections."""
        settings.PF_SYNC_CREATED_AFTER = None

        # Explicit in-memory URI as suggested, mapped to StaticPool to keep schema alive
        # for the duration of a single test's async execution context.
        self.test_engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.test_session_maker = sessionmaker(bind=self.test_engine, class_=AsyncSession, expire_on_commit=False)

        # Intercept the worker's DB connection globally
        self.session_patcher = patch("src.domain.pf_jira.tasks.async_session_maker", self.test_session_maker)
        self.session_patcher.start()

        # Isolate metadata per test run to handle remaining ghost artifacts
        SQLModel.metadata.clear()

        # Build the schema in memory
        async with self.test_engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        # Bootstrap default DomainConfig
        async with self.test_session_maker() as session:
            config = DomainConfig(
                domain_name="pf_jira",
                is_active=True,
                polling_interval_seconds=300,
                default_jira_project="HR",
                jira_pf_task_id_custom_field="customfield_10048",
            )
            session.add(config)
            await session.commit()

        # Reusable Redis Mock Context
        self.mock_redis = AsyncMock()
        self.mock_redis.lock.side_effect = dummy_async_context
        self.mock_redis.get.return_value = None
        self.mock_redis.set.return_value = None
        self.ctx = {"redis": self.mock_redis, "job_id": "test_job_1"}

    async def asyncTearDown(self) -> None:
        """Destroys the in-memory database and restores the original engine."""
        self.session_patcher.stop()

        async with self.test_engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.drop_all)

        await self.test_engine.dispose()
