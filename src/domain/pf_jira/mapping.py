import logging
import re
from typing import Any

from sqlalchemy.orm import selectinload
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.domain.pf_jira.models import RoutingAction, RoutingRule
from src.domain.pf_jira.resolver import FieldDataResolver, SchemaValidationError

logger = logging.getLogger(__name__)

JIRA_CUSTOM_FIELD_START_DATE = "customfield_10015"


def build_adf_description(task: dict[str, Any]) -> dict[str, Any]:
    """Generates a strict Atlassian Document Format (ADF) AST for the issue description."""
    desc = task.get("description_plain") or "No description provided."
    assoc_name = task.get("associated_to", {}).get("full_name", "Unknown")
    deadline = task.get("ends_on") or task.get("starts_on") or "None"

    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"text": desc, "type": "text"}]},
            {"type": "rule"},
            {
                "type": "paragraph",
                "content": [
                    {"text": "PeopleForce Metadata\n", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f"Subject: {assoc_name}\n", "type": "text"},
                    {"text": f"Deadline: {deadline}", "type": "text"},
                ],
            },
        ],
    }


async def evaluate_routing_rules(
    session: AsyncSession, pf_payload: dict[str, Any], resolver: FieldDataResolver
) -> tuple[RoutingAction, dict[str, Any] | None]:
    """Evaluates the PeopleForce payload against active routing rules sequentially.

    Utilizes the injected FieldDataResolver to perform JIT schema validation
    and payload construction upon finding the first matching rule.

    Args:
        session: Active async database session.
        pf_payload: The source JSON payload from PeopleForce.
        resolver: The initialized payload transformation pipeline.

    Returns:
        tuple[RoutingAction, dict | None]: The action to take, and the fully
        validated Jira POST payload (if action is SYNC).

    Raises:
        SchemaValidationError: If the payload cannot be structurally reconciled
        with the upstream Jira CreateMeta schema.
    """
    # Eagerly load field_mappings to prevent DetachedInstanceError during async execution
    stmt = (
        select(RoutingRule)
        .where(RoutingRule.is_active.is_(True))
        .options(selectinload(RoutingRule.field_mappings))
        .order_by(RoutingRule.priority)
    )

    rules = (await session.exec(stmt)).all()

    for rule in rules:
        if _evaluate_conditions(rule, pf_payload):
            if rule.action == RoutingAction.DROP:
                logger.debug(f"Payload matched DROP rule {rule.id}.")
                return RoutingAction.DROP, None

            logger.info(f"Payload matched SYNC rule {rule.id}. Initiating resolver pipeline.")

            try:
                # The resolver handles caching, JSONPath extraction, and schema validation
                jira_payload = await resolver.build_payload(rule, pf_payload)
                return RoutingAction.SYNC, jira_payload

            except SchemaValidationError as e:
                logger.error(f"Rule {rule.id} failed structural validation: {e}")
                # Phase 2 Circuit Breaker triggers here:
                # e.g., await disable_rule(session, rule.id)
                raise
            except ValueError as e:
                logger.error(f"Rule {rule.id} failed data resolution: {e}")
                raise

    logger.debug("No routing rules matched. Defaulting to IGNORE.")
    return RoutingAction.DROP, None


def _evaluate_conditions(rule: RoutingRule, pf_payload: dict[str, Any]) -> bool:
    """Performs an implicit AND evaluation of all defined rule conditions.

    Args:
        rule: The RoutingRule instance.
        pf_payload: The source payload.

    Returns:
        bool: True if all defined conditions match, False otherwise.
    """
    if rule.condition_assignee_pattern:
        # Assuming PF payload structure {"assignee": {"email": "..."}}
        # Dot-notation resolver can be used here for deeply nested dynamic conditions later.
        assignee_email = pf_payload.get("assignee", {}).get("email", "")
        if not assignee_email or not re.search(rule.condition_assignee_pattern, assignee_email, re.IGNORECASE):
            return False

    if rule.condition_title_keyword:
        title = pf_payload.get("name", "") or pf_payload.get("title", "")
        if rule.condition_title_keyword.lower() not in title.lower():
            return False

    return True
