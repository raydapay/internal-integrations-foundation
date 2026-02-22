# scripts/migrate_rules.py
import asyncio

from sqlalchemy import text

from src.core.database import engine
from src.domain.pf_jira.models import SQLModel


async def migrate_rules() -> None:
    async with engine.begin() as conn:
        # 1. Create the new table
        await conn.run_sync(SQLModel.metadata.create_all)

        print("Migrating Project Rules...")
        project_rules = await conn.execute(text("SELECT * FROM projectroutingrule"))
        for pr in project_rules.mappings():
            await conn.execute(
                text("""
                INSERT INTO routingrule (priority, condition_assignee_pattern, target_jira_project, is_active)
                VALUES (:priority, :pattern, :project, :is_active)
                """),
                {
                    "priority": 100,  # Base priority for project routing
                    "pattern": pr["assignee_email_pattern"],
                    "project": pr["target_jira_project"],
                    "is_active": pr["is_active"],
                },
            )

        print("Migrating Task Type Rules...")
        task_rules = await conn.execute(text("SELECT * FROM tasktyperule"))
        for tr in task_rules.mappings():
            await conn.execute(
                text("""
                INSERT INTO routingrule (priority, condition_title_keyword, target_jira_task_type, is_active)
                VALUES (:priority, :keyword, :task_type, :is_active)
                """),
                {
                    "priority": tr["priority"],
                    "keyword": tr["title_keyword"],
                    "task_type": tr["jira_task_type"],
                    "is_active": tr["is_active"],
                },
            )

        # 3. Drop legacy tables
        print("Dropping legacy tables...")
        await conn.execute(text("DROP TABLE projectroutingrule"))
        await conn.execute(text("DROP TABLE tasktyperule"))

        print("Migration complete.")


if __name__ == "__main__":
    asyncio.run(migrate_rules())
