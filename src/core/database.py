from collections.abc import AsyncGenerator

from loguru import logger
from sqlalchemy import event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry
from sqlmodel.ext.asyncio.session import AsyncSession

from src.config.settings import settings

# Construct Async SQLite URL
DATABASE_URL = f"sqlite+aiosqlite:///{settings.SQLITE_DB_PATH}"

# Engine configuration with generous timeout for concurrent writers
engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={
        "check_same_thread": False,
        "timeout": 30.0,  # CRITICAL: 30s busy timeout for concurrent multi-process writes
    }
)


@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(
    dbapi_connection: DBAPIConnection,
    connection_record: ConnectionPoolEntry
) -> None:
    """Configures SQLite connection pragmas for concurrent access.

    Enables Write-Ahead Logging (WAL) and sets synchronous mode to NORMAL.
    This is required to allow concurrent readers and to serialize writes
    efficiently across multiple ARQ worker processes.

    Args:
        dbapi_connection: The raw DBAPI connection object.
        connection_record: The connection pool record.

    Raises:
        sqlite3.OperationalError: If the database is locked and pragmas cannot be set.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
    except Exception as e:
        logger.error(f"Failed to set SQLite pragmas: {e}")
        raise
    finally:
        cursor.close()


async_session_maker = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency provider for asynchronous database sessions.

    Yields:
        AsyncSession: An active SQLAlchemy/SQLModel asynchronous session.
    """
    async with async_session_maker() as session:
        yield session