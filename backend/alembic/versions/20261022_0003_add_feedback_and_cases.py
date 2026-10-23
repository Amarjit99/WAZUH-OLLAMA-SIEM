"""Migration adding analyst feedback columns to investigations and creating cases table.

Revision ID: 20261022_0003
Revises: 20261021_0002
Create Date: 2026-10-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20261022_0003"
down_revision: Union[str, None] = "20261021_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add feedback columns to investigations table
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(sa.Column("analyst_rating", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("analyst_notes", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("feedback_submitted_at", sa.DateTime(timezone=True), nullable=True))

    # 2. Create cases table
    op.create_table(
        "cases",
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="open", nullable=False),
        sa.Column("priority", sa.String(length=32), server_default="medium", nullable=False),
        sa.Column("assignee", sa.String(length=128), nullable=True),
        sa.Column("alert_id", sa.String(length=128), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.investigation_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("case_id"),
    )
    op.create_index("idx_cases_status", "cases", ["status"])
    op.create_index("idx_cases_priority", "cases", ["priority"])
    op.create_index("idx_cases_created_at", "cases", ["created_at"])
    op.create_index("idx_cases_alert_id", "cases", ["alert_id"])
    op.create_index("idx_cases_investigation_id", "cases", ["investigation_id"])
    op.create_index("idx_cases_assignee", "cases", ["assignee"])


def downgrade() -> None:
    op.drop_index("idx_cases_assignee", table_name="cases")
    op.drop_index("idx_cases_investigation_id", table_name="cases")
    op.drop_index("idx_cases_alert_id", table_name="cases")
    op.drop_index("idx_cases_created_at", table_name="cases")
    op.drop_index("idx_cases_priority", table_name="cases")
    op.drop_index("idx_cases_status", table_name="cases")
    op.drop_table("cases")

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_column("feedback_submitted_at")
        batch_op.drop_column("analyst_notes")
        batch_op.drop_column("analyst_rating")
