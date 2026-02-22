import sqlite3
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import text

from src.core.database import get_session, set_sqlite_pragma
from tests.base import BaseTest


class TestDatabaseCore(BaseTest):
    """Test suite for database configuration and connection pragmas."""

    async def test_get_session_yields_active_session(self) -> None:
        """Validates that the session dependency yields a functional AsyncSession."""
        # Route get_session to our ephemeral in-memory engine pool
        with patch("src.core.database.async_session_maker", self.test_session_maker):
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
        """Validates that SQLite pragmas are executed on connection creation."""
        mock_dbapi_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_dbapi_connection.cursor.return_value = mock_cursor

        # Execute the listener function manually
        set_sqlite_pragma(mock_dbapi_connection, MagicMock())

        # Verify the exact concurrent WAL pragmas were called
        mock_cursor.execute.assert_any_call("PRAGMA journal_mode=WAL")
        mock_cursor.execute.assert_any_call("PRAGMA synchronous=NORMAL")
        mock_cursor.execute.assert_any_call("PRAGMA busy_timeout=30000")
        mock_cursor.close.assert_called_once()
        mock_logger.assert_not_called()

    @patch("src.core.database.logger.error")
    def test_set_sqlite_pragma_exception_handling(self, mock_logger: MagicMock) -> None:
        """Validates exception logging and raising during pragma configuration."""
        mock_dbapi_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_dbapi_connection.cursor.return_value = mock_cursor

        # Simulate an operational error on the first pragma execution
        mock_cursor.execute.side_effect = sqlite3.OperationalError("database is locked")

        with self.assertRaises(sqlite3.OperationalError):
            set_sqlite_pragma(mock_dbapi_connection, MagicMock())

        mock_logger.assert_called_once()
        mock_cursor.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
