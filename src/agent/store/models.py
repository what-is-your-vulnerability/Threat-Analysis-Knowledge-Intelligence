"""PostgreSQL 표. 근거는 JSONB로 두고, scan_run은 작업 테이블을 겸한다."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "project"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    target_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Document(Base):
    __tablename__ = "document"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(Text)


class SecurityRuleRow(Base):
    __tablename__ = "security_rule"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20))
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSONB)


class ScanRun(Base):
    __tablename__ = "scan_run"
    __table_args__ = (Index("ix_scan_run_status_id", "status", "id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, done, failed
    previous_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_run.id", ondelete="SET NULL"))
    out_dir: Mapped[str | None] = mapped_column(Text)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VerdictRow(Base):
    __tablename__ = "verdict"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_run.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(30))
    data: Mapped[dict] = mapped_column(JSONB)


class FindingRow(Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_run.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(30))
    data: Mapped[dict] = mapped_column(JSONB)


class LedgerCellRow(Base):
    __tablename__ = "ledger_cell"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_run.id", ondelete="CASCADE"), index=True)
    subject: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)


class RunManifestRow(Base):
    __tablename__ = "run_manifest"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_run.id", ondelete="CASCADE"), index=True)
    manifest_id: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSONB)
