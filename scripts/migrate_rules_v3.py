import asyncio
import logging

from sqlalchemy import text

from src.core.database import engine

logger = logging.getLogger(__name__)


async def migrate_dehardcode() -> None:
    """Retroactively injects dynamic templates to replace removed python-level hardcoding."""
    async with engine.begin() as conn:
        print("1. Fetching all existing rules...")
        rules = await conn.execute(text("SELECT id FROM routingrule"))
        rule_ids = [row[0] for row in rules.fetchall()]

        for rule_id in rule_ids:
            # Get existing mappings to avoid collisions if admins already mapped them
            existing = await conn.execute(
                text("SELECT jira_field_id FROM rulefieldmapping WHERE rule_id = :rule_id"), {"rule_id": rule_id}
            )
            existing_fields = {row[0] for row in existing.fetchall()}

            inserts = []

            if "summary" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "summary",
                        "source_type": "template",
                        "source_value": "[PF] {{ title }} - {{ associated_to.full_name }}",
                    }
                )

            if "description" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "description",
                        "source_type": "template",
                        "source_value": (
                            "{{ description_plain }}\n\n*PeopleForce Metadata*\nSubject: "
                            "{{ associated_to.full_name }}\nDeadline: {{ ends_on }}"
                        ),
                    }
                )

            if "assignee" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "assignee",
                        "source_type": "pf_payload",
                        "source_value": "assigned_to.email",
                    }
                )

            if "reporter" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "reporter",
                        "source_type": "pf_payload",
                        "source_value": "created_by.email",
                    }
                )

            if "duedate" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "duedate",
                        "source_type": "pf_payload",
                        "source_value": "ends_on",
                    }
                )

            if "customfield_10015" not in existing_fields:
                inserts.append(
                    {
                        "rule_id": rule_id,
                        "jira_field_id": "customfield_10015",
                        "source_type": "pf_payload",
                        "source_value": "starts_on",
                    }
                )

            if inserts:
                await conn.execute(
                    text("""
                        INSERT INTO rulefieldmapping (rule_id, jira_field_id, source_type, source_value)
                        VALUES (:rule_id, :jira_field_id, :source_type, :source_value)
                    """),
                    inserts,
                )
        print("Migration complete. All legacy hardcoded fields converted to dynamic database templates.")


if __name__ == "__main__":
    asyncio.run(migrate_dehardcode())
