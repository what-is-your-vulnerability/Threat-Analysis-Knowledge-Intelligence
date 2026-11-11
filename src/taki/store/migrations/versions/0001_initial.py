"""처음 표."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None


def _scan_fk():
    return sa.Column("scan_id", sa.Integer, sa.ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False)


def _project_fk():
    return sa.Column("project_id", sa.Integer, sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False)


def upgrade() -> None:
    op.create_table(
        "project",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_path", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "document", sa.Column("id", sa.Integer, primary_key=True), _project_fk(),
        sa.Column("path", sa.Text, nullable=False),
    )
    op.create_index("ix_document_project_id", "document", ["project_id"])
    op.create_table(
        "security_rule", sa.Column("id", sa.Integer, primary_key=True), _project_fk(),
        sa.Column("rule_id", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("data", JSONB, nullable=False),
    )
    op.create_index("ix_security_rule_project_id", "security_rule", ["project_id"])
    op.create_table(
        "scan_run", sa.Column("id", sa.Integer, primary_key=True), _project_fk(),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("previous_scan_id", sa.Integer, sa.ForeignKey("scan_run.id", ondelete="SET NULL")),
        sa.Column("out_dir", sa.Text),
        sa.Column("exit_code", sa.Integer),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_run_project_id", "scan_run", ["project_id"])
    op.create_index("ix_scan_run_status_id", "scan_run", ["status", "id"])
    op.create_table(
        "verdict", sa.Column("id", sa.Integer, primary_key=True), _scan_fk(),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("data", JSONB, nullable=False),
    )
    op.create_index("ix_verdict_scan_id", "verdict", ["scan_id"])
    op.create_table(
        "finding", sa.Column("id", sa.Integer, primary_key=True), _scan_fk(),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("data", JSONB, nullable=False),
    )
    op.create_index("ix_finding_scan_id", "finding", ["scan_id"])
    op.create_table(
        "ledger_cell", sa.Column("id", sa.Integer, primary_key=True), _scan_fk(),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
    )
    op.create_index("ix_ledger_cell_scan_id", "ledger_cell", ["scan_id"])
    op.create_table(
        "run_manifest", sa.Column("id", sa.Integer, primary_key=True), _scan_fk(),
        sa.Column("manifest_id", sa.String(64), nullable=False),
        sa.Column("data", JSONB, nullable=False),
    )
    op.create_index("ix_run_manifest_scan_id", "run_manifest", ["scan_id"])


def downgrade() -> None:
    for table in ("run_manifest", "ledger_cell", "finding", "verdict", "scan_run", "security_rule", "document", "project"):
        op.drop_table(table)
