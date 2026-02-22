from dataclasses import dataclass

from fastapi import Form, Query

from src.domain.pf_jira.models import RoutingAction


@dataclass
class AuditQueryParams:
    """Encapsulates GET query parameters for the Audit Log dashboard."""

    query: str | None = Query(default=None, description="Search substring")
    operation: str | None = Query(default=None, description="Filter by SyncOperation enum")
    page: int = Query(default=1, ge=1, description="Pagination offset multiplier")


@dataclass
class RoutingRuleForm:
    """Encapsulates POST form data for creating or updating routing rules."""

    priority: int = Form(default=100)
    action: RoutingAction = Form(default=RoutingAction.SYNC)
    condition_assignee_pattern: str | None = Form(default=None)
    condition_title_keyword: str | None = Form(default=None)
    target_jira_project: str | None = Form(default=None)
    target_jira_task_type: str | None = Form(default=None)
    target_jira_labels: str | None = Form(default=None)
    target_assignee_email: str | None = Form(default=None)
    target_reporter_email: str | None = Form(default=None)


@dataclass
class UserAccessForm:
    """Encapsulates POST form data for user RBAC modifications."""

    role: str = Form(...)
    is_active: bool = Form(default=False)


@dataclass
class UserProvisionForm:
    """Encapsulates POST form data for JIT user provisioning."""

    email: str = Form(...)
    role: str = Form(...)
