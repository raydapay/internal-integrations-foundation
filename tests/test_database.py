import sqlite3
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import text
from sqlmodel import SQLModel

from src.core.database import engine, get_session, set_sqlite_pragma


class TestDatabaseCore(unittest.IsolatedAsyncioTestCase):
    """Test suite for database configuration and connection pragmas."""

    async def asyncSetUp(self) -> None:
        """Initializes the in-memory SQLite schema for testing."""
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def test_get_session_yields_active_session(self) -> None:
        """Validates that the session dependency yields a functional AsyncSession."""
        session_gen = get_session()
        session = await anext(session_gen)

        # Execute a simple scalar query to ensure connectivity
        result = await session.exec(text("SELECT 1"))
        self.assertEqual(result.first()[0], 1)

        # Teardown the generator
        try:
            await anext(session_gen)
        except StopAsyncIteration:
            pass

    @patch("src.core.database.logger.error")
    def test_set_sqlite_pragma_execution(self, mock_logger: MagicMock) -> None:
        """Validates that SQLite pragmas are executed on connection creation.

        Args:
            mock_logger: Mocked Loguru logger to verify error handling.
        """
        mock_dbapi_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_dbapi_connection.cursor.return_value = mock_cursor

        # Execute the listener function manually
        set_sqlite_pragma(mock_dbapi_connection, MagicMock())

        # Verify the exact pragmas were called
        mock_cursor.execute.assert_any_call("PRAGMA journal_mode=WAL")
        mock_cursor.execute.assert_any_call("PRAGMA synchronous=NORMAL")
        mock_cursor.execute.assert_any_call("PRAGMA busy_timeout=30000")
        mock_cursor.close.assert_called_once()
        mock_logger.assert_not_called()

    @patch("src.core.database.logger.error")
    def test_set_sqlite_pragma_exception_handling(self, mock_logger: MagicMock) -> None:
        """Validates exception logging and raising during pragma configuration.

        Args:
            mock_logger: Mocked Loguru logger.
        """
        mock_dbapi_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_dbapi_connection.cursor.return_value = mock_cursor

        # Simulate an operational error on the first pragma execution
        mock_cursor.execute.side_effect = sqlite3.OperationalError("database is locked")

        with self.assertRaises(sqlite3.OperationalError):
            set_sqlite_pragma(mock_dbapi_connection, MagicMock())

        mock_logger.assert_called_once()
        mock_cursor.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()