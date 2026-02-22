import asyncio

from sqlalchemy import text

from src.core.database import engine


async def run_migration():
    queries = [
        "ALTER TABLE domainconfig ADD COLUMN jira_pf_task_id_custom_field VARCHAR DEFAULT 'customfield_10048'",
        "ALTER TABLE domainconfig ADD COLUMN jira_fallback_account_id VARCHAR",
    ]

    async with engine.begin() as conn:
        for query in queries:
            try:
                await conn.execute(text(query))
                print(f"Success: {query}")
            except Exception as e:
                print(f"Skipped: {e}")


if __name__ == "__main__":
    asyncio.run(run_migration())
