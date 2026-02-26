import asyncio

from sqlalchemy import text

from src.core.database import engine
from src.domain.pf_jira.models import SQLModel


async def migrate_to_dynamic_schemas() -> None:
    """Migrates static RoutingRule mutations to the normalized RuleFieldMapping table."""
    async with engine.begin() as conn:
        print("1. Creating RuleFieldMapping table...")
        await conn.run_sync(SQLModel.metadata.create_all)

        print("2. Extracting active DomainConfig...")
        config_res = await conn.execute(
            text("SELECT jira_pf_task_id_custom_field FROM domainconfig WHERE domain_name = 'pf_jira'")
        )
        config_row = config_res.first()
        task_type_field_id = config_row[0] if config_row else "customfield_10048"

        print("3. Migrating flat columns to normalized mappings...")
        rules = await conn.execute(
            text(
                "SELECT id, target_jira_task_type, target_jira_labels, target_assignee_email, target_reporter_email "
                "FROM routingrule"
            )
        )

        insert_stmt = text("""
            INSERT INTO rulefieldmapping (rule_id, jira_field_id, source_type, source_value)
            VALUES (:rule_id, :jira_field_id, 'static', :source_value)
        """)

        for row in rules.mappings():
            rule_id = row["id"]

            if row["target_jira_task_type"]:
                await conn.execute(
                    insert_stmt,
                    {
                        "rule_id": rule_id,
                        "jira_field_id": task_type_field_id,
                        "source_value": row["target_jira_task_type"],
                    },
                )

            if row["target_jira_labels"]:
                await conn.execute(
                    insert_stmt,
                    {"rule_id": rule_id, "jira_field_id": "labels", "source_value": row["target_jira_labels"]},
                )

            if row["target_assignee_email"]:
                await conn.execute(
                    insert_stmt,
                    {"rule_id": rule_id, "jira_field_id": "assignee", "source_value": row["target_assignee_email"]},
                )

            if row["target_reporter_email"]:
                await conn.execute(
                    insert_stmt,
                    {"rule_id": rule_id, "jira_field_id": "reporter", "source_value": row["target_reporter_email"]},
                )

        print("4. Rebuilding RoutingRule to drop legacy columns...")
        # SQLite constraint bypass for column drops
        await conn.execute(
            text("""
            CREATE TABLE routingrule_new (
                id INTEGER PRIMARY KEY,
                priority INTEGER,
                condition_assignee_pattern VARCHAR,
                condition_title_keyword VARCHAR,
                action VARCHAR,
                target_jira_project VARCHAR,
                is_active BOOLEAN
            )
        """)
        )

        await conn.execute(
            text("""
            INSERT INTO routingrule_new (
                id, priority, condition_assignee_pattern, condition_title_keyword,
                action, target_jira_project, is_active
                )
            SELECT id, priority, condition_assignee_pattern, condition_title_keyword,
            action, target_jira_project, is_active FROM routingrule
        """)
        )

        await conn.execute(text("DROP TABLE routingrule"))
        await conn.execute(text("ALTER TABLE routingrule_new RENAME TO routingrule"))

        print("Migration complete.")


if __name__ == "__main__":
    asyncio.run(migrate_to_dynamic_schemas())
