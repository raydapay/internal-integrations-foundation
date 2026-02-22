import asyncio

from sqlalchemy import text

from src.core.database import engine


async def migrate() -> None:
    async with engine.begin() as conn:
        print("Migrating routingrule table...")
        await conn.execute(text("ALTER TABLE routingrule ADD COLUMN action VARCHAR NOT NULL DEFAULT 'sync'"))
        await conn.execute(text("ALTER TABLE routingrule ADD COLUMN target_assignee_email VARCHAR"))
        await conn.execute(text("ALTER TABLE routingrule ADD COLUMN target_reporter_email VARCHAR"))
        print("Migration complete. Added 'action', 'target_assignee_email', and 'target_reporter_email'.")


if __name__ == "__main__":
    asyncio.run(migrate())
