import logging
from typing import Any

from sqlalchemy.orm import selectinload
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.domain.pf_jira.models import RoutingAction, RoutingRule
from src.domain.pf_jira.resolver import FieldDataResolver, SchemaValidationError

logger = logging.getLogger(__name__)


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


def _evaluate_conditions(rule: RoutingRule, pf_task: dict[str, Any]) -> bool:
    """Evaluates if a PeopleForce task matches a RoutingRule's conditions, with verbose debugging."""

    # 1. Title Condition
    if rule.condition_title_keyword:
        keyword = rule.condition_title_keyword.strip().lower()
        title = pf_task.get("title", "").lower()
        if keyword not in title:
            return False

    # 2. Assignee Condition
    if rule.condition_assignee_pattern:
        expected_pattern = rule.condition_assignee_pattern.strip().lower()

        # Safely extract the email, handling cases where 'assigned_to' is None or missing
        assigned_to_obj = pf_task.get("assigned_to") or {}
        actual_email = assigned_to_obj.get("email", "").strip().lower()

        logger.debug(
            f"[Rule #{rule.id} Eval] Expected Assignee: '{expected_pattern}' | Actual PF Payload: '{actual_email}'"
        )

        if expected_pattern not in actual_email:
            logger.debug(f"[Rule #{rule.id} Eval] ❌ REJECTED: '{expected_pattern}' not found in '{actual_email}'")
            return False

        logger.debug(f"[Rule #{rule.id} Eval] ✅ MATCHED: Assignee condition passed.")

    return True
