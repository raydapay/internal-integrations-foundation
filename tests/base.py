import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# Ensure canonical imports are resolved
import src.domain.users.models  # noqa: F401
from src.config.settings import settings
from src.domain.pf_jira.models import DomainConfig


@asynccontextmanager
async def dummy_async_context(*args, **kwargs):
    """Provides a safe, non-blocking mock for 'async with' Redis lock blocks."""
    yield MagicMock()


class BaseTest(unittest.IsolatedAsyncioTestCase):
    """Base test class providing strict, ephemeral database isolation."""

    async def asyncSetUp(self) -> None:
        """Bootstraps a pure in-memory database and intercepts worker connections."""
        settings.PF_SYNC_CREATED_AFTER = None

        # Explicit in-memory URI mapped to StaticPool to keep schema alive
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
            )
            session.add(config)
            await session.commit()

        # Reusable Redis Mock Context
        self.mock_redis = AsyncMock()

        # Isolate the lock method from the AsyncMock hierarchy so it returns a
        # context manager synchronously, satisfying the 'async with' protocol.
        self.mock_redis.lock = MagicMock(side_effect=dummy_async_context)
        self.mock_redis.get.return_value = None
        self.mock_redis.set.return_value = None
        self.ctx = {"redis": self.mock_redis, "job_id": "test_job_1"}
        # Globally suppress all Slack/Telegram broadcasts during test execution
        self.core_notify_patcher = patch("src.core.notifications.notify", new_callable=AsyncMock)
        self.tasks_notify_patcher = patch("src.domain.pf_jira.tasks.notify", new_callable=AsyncMock)

        self.mock_core_notify = self.core_notify_patcher.start()
        self.mock_tasks_notify = self.tasks_notify_patcher.start()

    async def asyncTearDown(self) -> None:
        """Destroys the in-memory database and restores the original engine."""
        self.session_patcher.stop()
        self.core_notify_patcher.stop()
        self.tasks_notify_patcher.stop()

        async with self.test_engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.drop_all)

        await self.test_engine.dispose()
