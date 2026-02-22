from datetime import datetime
from enum import StrEnum

from sqlmodel import Field, SQLModel


class UserRole(StrEnum):
    """Defines the hierarchical RBAC tiers for system access."""

    SYSTEM_ADMIN = "system_admin"
    PF_JIRA_ADMIN = "pf_jira_admin"
    VIEWER = "viewer"


class User(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    """Represents a system user authenticated via Google SSO."""

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    full_name: str
    avatar_url: str | None = None
    is_active: bool = Field(default=False)  # Requires manual activation
    role: UserRole = Field(default=UserRole.VIEWER)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: datetime = Field(default_factory=datetime.utcnow)
