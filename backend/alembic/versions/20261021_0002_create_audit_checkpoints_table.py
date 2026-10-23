"""Migration creating audit_checkpoints table for ADR-013.

Revision ID: 20261021_0002
Revises: 20261021_0001
Create Date: 2026-10-21

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20261021_0002"
down_revision: Union[str, None] = "20261021_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_checkpoints",
        sa.Column("checkpoint_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="v1", nullable=False),
        sa.Column("checkpoint_sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_start_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_end_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_included_audit_id", sa.String(length=36), nullable=False),
        sa.Column("last_included_audit_id", sa.String(length=36), nullable=False),
        sa.Column("last_included_event_hash", sa.String(length=64), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("pruned_events_digest", sa.String(length=64), nullable=False),
        sa.Column("previous_checkpoint_id", sa.String(length=36), nullable=True),
        sa.Column("previous_checkpoint_hash", sa.String(length=64), nullable=False),
        sa.Column("checkpoint_digest", sa.String(length=64), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=32), server_default="NONE", nullable=False),
        sa.Column("signature_value", sa.Text(), nullable=True),
        sa.Column("signing_key_id", sa.String(length=64), nullable=True),
        sa.Column("archive_file_path", sa.String(length=255), nullable=True),
        sa.Column("archive_sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="ACTIVE", nullable=False),
        sa.PrimaryKeyConstraint("checkpoint_id"),
        sa.UniqueConstraint("checkpoint_sequence", name="uq_checkpoint_sequence"),
    )
    op.create_index("idx_checkpoints_seq", "audit_checkpoints", ["checkpoint_sequence"])
    op.create_index("idx_checkpoints_hash", "audit_checkpoints", ["checkpoint_digest"])
    op.create_index("idx_checkpoints_last_event", "audit_checkpoints", ["last_included_event_hash"])


def downgrade() -> None:
    op.drop_index("idx_checkpoints_last_event", table_name="audit_checkpoints")
    op.drop_index("idx_checkpoints_hash", table_name="audit_checkpoints")
    op.drop_index("idx_checkpoints_seq", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
