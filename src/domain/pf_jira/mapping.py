from typing import Any

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.config.settings import settings
from src.domain.pf_jira.models import RoutingAction, RoutingRule

# JIRA_CUSTOM_FIELD_TASK_TYPE = "customfield_10048"
JIRA_CUSTOM_FIELD_START_DATE = "customfield_10015"
# FALLBACK_ACCOUNT_ID = "5b10ac8d136ee314ce397db6"


async def evaluate_routing_rules(session: AsyncSession, task: dict[str, Any]) -> dict[str, Any]:
    """Evaluates the firewall-style routing matrix to determine Jira targets."""
    statement = select(RoutingRule).where(RoutingRule.is_active).order_by(RoutingRule.priority)
    rules = (await session.exec(statement)).all()

    assignee_email = task.get("assigned_to", {}).get("email", "").lower()
    title = task.get("title", "").lower()

    # Base state prior to evaluation
    result = {
        "action": RoutingAction.SYNC,
        "project": settings.PF_DEFAULT_JIRA_PROJECT,
        "task_type": None,
        "labels": [],
        "assignee_email": None,
        "reporter_email": None,
    }

    for rule in rules:
        match = True

        if rule.condition_assignee_pattern and rule.condition_assignee_pattern.lower() not in assignee_email:
            match = False
        if rule.condition_title_keyword and rule.condition_title_keyword.lower() not in title:
            match = False

        if match:
            result["action"] = rule.action
            if rule.target_jira_project:
                result["project"] = rule.target_jira_project
            if rule.target_jira_task_type:
                result["task_type"] = rule.target_jira_task_type
            if rule.target_jira_labels:
                result["labels"] = [label.strip() for label in rule.target_jira_labels.split(",") if label.strip()]
            if rule.target_assignee_email:
                result["assignee_email"] = rule.target_assignee_email
            if rule.target_reporter_email:
                result["reporter_email"] = rule.target_reporter_email

            # The Firewall terminates on the first matched rule
            break

    return result


def build_adf_description(task: dict[str, Any]) -> dict[str, Any]:
    """Constructs a strictly compliant Atlassian Document Format (ADF) AST."""
    desc_plain = task.get("description_plain") or "No description provided in PeopleForce."

    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": desc_plain}]},
            {"type": "rule"},
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "PeopleForce Metadata\n",
                        "marks": [{"type": "strong"}],
                    },
                    {
                        "type": "text",
                        "text": f"Subject: {task.get('associated_to', {}).get('full_name', 'None')}\n",
                    },
                    {"type": "text", "text": f"Deadline: {task.get('starts_on', 'None')}"},
                ],
            },
        ],
    }
