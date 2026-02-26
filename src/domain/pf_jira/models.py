from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar

from sqlmodel import Field, Index, Relationship, SQLModel, UniqueConstraint


class MappingSourceType(StrEnum):
    """Defines the origin of the data injected into the Jira field."""

    STATIC = "static"
    PF_PAYLOAD = "pf_payload"  # Indicates source_value is a JSONPath (e.g., '$.assigned_to.email')
    TEMPLATE = "template"  # Indicates source_value contains interpolation tags (e.g., 'Task: {{ title }}')


class RuleFieldMapping(SQLModel, table=True):
    """Normalized key-value mapping for dynamic Jira field injection."""

    id: int | None = Field(default=None, primary_key=True)
    rule_id: int = Field(foreign_key="routingrule.id", index=True, ondelete="CASCADE")

    jira_field_id: str = Field(index=True, description="The internal Jira ID, e.g., 'issuetype', 'customfield_10048'")
    source_type: MappingSourceType = Field(default=MappingSourceType.STATIC)
    source_value: str = Field(description="The hardcoded string, or the PF payload JSONPath.")
    rule: "RoutingRule" = Relationship(back_populates="field_mappings")


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
    condition_assignee_pattern: str | None = Field(default=None)
    condition_title_keyword: str | None = Field(default=None)

    # --- Base Target ---
    action: RoutingAction = Field(default=RoutingAction.SYNC)
    target_jira_project: str | None = Field(default=None, description="Jira Project Key, e.g., 'IT', 'HR'")
    is_active: bool = Field(default=True)

    # --- Dynamic Field Mutations ---
    field_mappings: list[RuleFieldMapping] = Relationship(
        back_populates="rule", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class SyncOperation(StrEnum):
    """Categorizes the type of state mutation performed during reconciliation."""

    CREATE = "create"
    UPDATE = "update"
    SKIP = "skip"
    ERROR = "error"


class SyncAuditLog(SQLModel, table=True):
    """Immutable append-only ledger for human-readable integration telemetry."""

    __table_args__: ClassVar[dict[str, bool]] = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    direction: str = Field(default="PF ➡️ Jira", description="Data flow vector")

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
    jira_fallback_account_id: str | None = Field(default=None)
    jira_tracking_label: str = Field(default="PeopleForce")
    jira_entity_property_key: str = Field(default="pf_sync_metadata")

    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
