from datetime import UTC, datetime
from enum import StrEnum

from sqlmodel import Field, Index, SQLModel, UniqueConstraint


class SyncState(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("pf_entity_type", "pf_entity_id", name="uq_pf_entity"),
        Index("ix_pf_entity_lookup", "pf_entity_type", "pf_entity_id"),
    )
    """Tracks the synchronization state between PeopleForce and Jira.

    This table prevents duplicate task creation and allows for delta-sync
    calculations in the absence of PeopleForce webhooks.
    """

    id: int | None = Field(default=None, primary_key=True)

    # PeopleForce Identifiers
    pf_entity_type: str = Field(index=True)  # e.g., 'employee', 'onboarding_task'
    pf_entity_id: str = Field(index=True)

    # Jira Identifiers
    jira_issue_key: str = Field(unique=True, index=True)  # e.g., 'HR-123'
    jira_issue_id: str

    # State Metadata
    last_sync_hash: str  # MD5/SHA of the PF entity state to detect changes
    is_completed: bool = Field(default=False)
    last_updated_at: datetime = Field(default_factory=datetime.utcnow)


class RoutingAction(StrEnum):
    """Defines the execution behavior when a routing rule is matched."""

    SYNC = "SYNC"
    DROP = "DROP"


class RoutingRule(SQLModel, table=True):
    """Unified, priority-based routing matrix for Jira task dispatch."""

    id: int | None = Field(default=None, primary_key=True)
    priority: int = Field(default=100, index=True, description="Lower number evaluates first")

    # --- Conditions (Implicit AND) ---
    condition_assignee_pattern: str | None = Field(
        default=None, description="Exact email or domain like '@it.todapay.com'"
    )
    condition_title_keyword: str | None = Field(default=None, description="Lowercase keyword, e.g., 'уведомление'")

    # --- Mutations (Applied if rule matches) ---
    action: RoutingAction = Field(default=RoutingAction.SYNC, description="Whether to SYNC or DROP the matched task")
    target_jira_project: str | None = Field(default=None, description="Jira Project Key, e.g., 'IT', 'HR'")
    target_jira_task_type: str | None = Field(
        default=None, description="Exact Jira dropdown value, e.g., 'Организационная'"
    )
    target_jira_labels: str | None = Field(default=None, description="Comma-separated labels to inject")
    target_assignee_email: str | None = Field(default=None, description="Overrides the default PeopleForce assignee")
    target_reporter_email: str | None = Field(default=None, description="Overrides the default PeopleForce reporter")

    is_active: bool = Field(default=True)


class SyncOperation(StrEnum):
    """Categorizes the type of state mutation performed during reconciliation."""

    CREATE = "create"
    UPDATE = "update"
    SKIP = "skip"
    ERROR = "error"


class SyncAuditLog(SQLModel, table=True):
    """Immutable append-only ledger for human-readable integration telemetry."""

    __table_args__ = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    direction: str = Field(default="PF ➡️Jira", description="Data flow vector")

    pf_task_id: str | None = Field(default=None, index=True)
    jira_issue_key: str | None = Field(default=None, index=True)

    operation: SyncOperation = Field(index=True)
    details: str = Field(description="JSON formatted string of the applied deltas or errors")


class DomainConfig(SQLModel, table=True):
    """Mutable runtime configuration for an integration domain."""

    id: int | None = Field(default=None, primary_key=True)
    domain_name: str = Field(default="pf_jira", unique=True, index=True)
    is_active: bool = Field(default=True)
    polling_interval_seconds: int = Field(default=300)
    default_jira_project: str | None = Field(default=None)

    # System Health & Alerting
    health_check_interval_seconds: int = Field(default=900)
    alert_mem_threshold_pct: float = Field(default=90.0)
    alert_disk_threshold_pct: float = Field(default=90.0)
    alert_queue_depth_threshold: int = Field(default=500)
    # Jira Integration Constants
    jira_pf_task_id_custom_field: str = Field(default="customfield_10048")
    jira_fallback_account_id: str | None = Field(default=None)

    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
