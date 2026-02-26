import asyncio
import logging

from sqlalchemy import text

from src.core.database import engine

logger = logging.getLogger(__name__)


async def run_migration() -> None:
    """Executes the Phase 2 schema migration for externalizing Jira lineage tracking.

    Injects tracking label and entity property configuration columns into
    the DomainConfig SQLite table. Fails gracefully if columns already exist.
    """
    queries = [
        "ALTER TABLE domainconfig ADD COLUMN jira_tracking_label VARCHAR DEFAULT 'PeopleForce'",
        "ALTER TABLE domainconfig ADD COLUMN jira_entity_property_key VARCHAR DEFAULT 'pf_sync_metadata'",
    ]

    print("Executing DomainConfig v2 migration...")
    async with engine.begin() as conn:
        for query in queries:
            try:
                await conn.execute(text(query))
                print(f"Success: {query}")
            except Exception as e:
                # SQLite raises an OperationalError if the column already exists.
                print(f"Skipped (column likely exists): {e}")

    print("Migration complete.")


if __name__ == "__main__":
    asyncio.run(run_migration())
