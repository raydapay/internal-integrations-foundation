import asyncio

from sqlalchemy import text

from src.core.database import engine


async def run_migration():
    queries = [
        "ALTER TABLE domainconfig ADD COLUMN health_check_interval_seconds INTEGER DEFAULT 900",
        "ALTER TABLE domainconfig ADD COLUMN alert_mem_threshold_pct REAL DEFAULT 90.0",
        "ALTER TABLE domainconfig ADD COLUMN alert_disk_threshold_pct REAL DEFAULT 90.0",
        "ALTER TABLE domainconfig ADD COLUMN alert_queue_depth_threshold INTEGER DEFAULT 500",
    ]

    print("Starting database migration...")
    async with engine.begin() as conn:
        for query in queries:
            try:
                await conn.execute(text(query))
                print(f"Success: {query}")
            except Exception as e:
                # If the column already exists, SQLite throws an OperationalError, which we can safely ignore.
                print(f"Skipped (column likely exists): {e}")

    print("Migration complete.")


if __name__ == "__main__":
    asyncio.run(run_migration())
