from dataclasses import dataclass

from fastapi import Form, Query
from pydantic import BaseModel, ConfigDict

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


class PFUserReference(BaseModel):
    """Standardized nested user object returned by PeopleForce."""

    id: int
    full_name: str
    email: str | None = None
    type: str | None = None


class PeopleForceTaskPayload(BaseModel):
    """Immutable representation of the PeopleForce Task JSON payload.

    Acts as the single source of truth for payload structure and provides
    example schemas for dynamic UI rendering in the Admin dashboard.
    """

    id: int
    type: str
    title: str
    starts_on: str | None = None
    ends_on: str | None = None
    completed_at: str | None = None
    completed: bool
    description: str | None = None
    description_plain: str | None = None
    assigned_to: PFUserReference | None = None
    associated_to: PFUserReference | None = None
    created_by: PFUserReference | None = None
    created_at: str | None = None
    updated_at: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": 7654321,
                    "type": "Tasks::General",
                    "title": "Nice task title",
                    "starts_on": "2026-02-27",
                    "ends_on": None,
                    "completed_at": None,
                    "completed": False,
                    "description": "Rich HTML text with <a href=...>links</a>",
                    "description_plain": "Plain text fallback",
                    "assigned_to": {"id": 123456, "full_name": "Jane Doe", "email": "jane@example.com"},
                    "associated_to": {
                        "id": 123458,
                        "type": "Employee",
                        "full_name": "Bobby Smith",
                        "email": "bobby@example.com",
                    },
                    "created_by": {"id": 123457, "full_name": "John Doe", "email": "john@example.com"},
                    "created_at": "2026-02-23T10:40:50.361Z",
                    "updated_at": "2026-02-23T10:41:34.362Z",
                }
            ]
        }
    )
