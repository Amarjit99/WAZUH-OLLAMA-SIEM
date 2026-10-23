"""Initial migration creating 7 approved persistence tables.

Revision ID: 20261021_0001
Revises: None
Create Date: 2026-10-21

Conforms strictly to specs/PHASE_7_DATABASE_SCHEMA.md.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20261021_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. investigations
    op.create_table(
        "investigations",
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=128), nullable=False),
        sa.Column("run_sequence", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="queued", nullable=False),
        sa.Column("primary_rule_id", sa.String(length=64), nullable=False),
        sa.Column("primary_rule_level", sa.Integer(), nullable=True),
        sa.Column("primary_agent_name", sa.String(length=255), nullable=True),
        sa.Column("query_window_minutes", sa.Integer(), server_default="30", nullable=False),
        sa.Column("max_evidence_items", sa.Integer(), server_default="10", nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("execution_duration_ms", sa.Integer(), nullable=True),
        sa.Column("actor_id", sa.String(length=64), server_default="local_analyst", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("investigation_id"),
        sa.UniqueConstraint("alert_id", "run_sequence", name="uq_alert_run"),
    )
    op.create_index("idx_investigations_alert_id", "investigations", ["alert_id"])
    op.create_index("idx_investigations_created_at", "investigations", [sa.text("created_at DESC")])
    op.create_index("idx_investigations_status", "investigations", ["status"])
    op.create_index("idx_investigations_rule", "investigations", ["primary_rule_id"])
    op.create_index("idx_investigations_agent", "investigations", ["primary_agent_name"])
    op.create_index("idx_investigations_actor", "investigations", ["actor_id"])

    # 2. investigation_results
    op.create_table(
        "investigation_results",
        sa.Column("result_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("model_tag", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("confidence_label", sa.String(length=16), nullable=False),
        sa.Column("disclaimer", sa.Text(), nullable=False),
        sa.Column("limitations_json", sa.Text(), server_default="[]", nullable=False),
        sa.Column("warnings_json", sa.Text(), server_default="[]", nullable=False),
        sa.Column("correlation_status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.investigation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("result_id"),
        sa.UniqueConstraint("investigation_id", name="uq_result_investigation"),
    )
    op.create_index("idx_results_confidence", "investigation_results", ["confidence_label"])

    # 3. investigation_facts
    op.create_table(
        "investigation_facts",
        sa.Column("fact_id", sa.String(length=36), nullable=False),
        sa.Column("result_id", sa.String(length=36), nullable=False),
        sa.Column("fact_identifier", sa.String(length=16), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("cited_evidence_ids_json", sa.Text(), server_default="[]", nullable=False),
        sa.ForeignKeyConstraint(
            ["result_id"],
            ["investigation_results.result_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("fact_id"),
    )
    op.create_index("idx_facts_result", "investigation_facts", ["result_id"])

    # 4. investigation_hypotheses
    op.create_table(
        "investigation_hypotheses",
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("result_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_identifier", sa.String(length=16), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("uncertainty", sa.String(length=16), nullable=False),
        sa.Column("cited_evidence_ids_json", sa.Text(), server_default="[]", nullable=False),
        sa.ForeignKeyConstraint(
            ["result_id"],
            ["investigation_results.result_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("hypothesis_id"),
    )
    op.create_index("idx_hypotheses_result", "investigation_hypotheses", ["result_id"])

    # 5. investigation_checks
    op.create_table(
        "investigation_checks",
        sa.Column("check_id", sa.String(length=36), nullable=False),
        sa.Column("result_id", sa.String(length=36), nullable=False),
        sa.Column("check_identifier", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("is_read_only", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.ForeignKeyConstraint(
            ["result_id"],
            ["investigation_results.result_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("check_id"),
    )
    op.create_index("idx_checks_result", "investigation_checks", ["result_id"])

    # 6. investigation_evidence_snapshots
    op.create_table(
        "investigation_evidence_snapshots",
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_id", sa.String(length=16), nullable=False),
        sa.Column("source_record_id", sa.String(length=128), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_level", sa.Integer(), nullable=True),
        sa.Column("rule_description", sa.Text(), nullable=True),
        sa.Column("agent_name", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("correlation_reason", sa.String(length=64), nullable=True),
        sa.Column("correlation_qualifier", sa.String(length=128), nullable=True),
        sa.Column("raw_evidence_ref", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.investigation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("investigation_id", "evidence_id", name="uq_investigation_evidence"),
    )
    op.create_index("idx_snapshots_investigation", "investigation_evidence_snapshots", ["investigation_id"])
    op.create_index("idx_snapshots_source_record", "investigation_evidence_snapshots", ["source_record_id"])

    # 7. audit_events
    op.create_table(
        "audit_events",
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("audit_id"),
    )
    op.create_index("idx_audit_timestamp", "audit_events", [sa.text("timestamp DESC")])
    op.create_index("idx_audit_action", "audit_events", ["action"])
    op.create_index("idx_audit_resource", "audit_events", ["resource_type", "resource_id"])
    op.create_index("idx_audit_event_hash", "audit_events", ["event_hash"])


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.drop_table("audit_events")
    op.drop_table("investigation_evidence_snapshots")
    op.drop_table("investigation_checks")
    op.drop_table("investigation_hypotheses")
    op.drop_table("investigation_facts")
    op.drop_table("investigation_results")
    op.drop_table("investigations")
