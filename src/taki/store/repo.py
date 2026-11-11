"""DB 접근과 worker 한 번 실행. 실패한 작업은 빈 결과가 아니라 failed로 남긴다."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from taki.config import AgentConfig
from taki.core.orchestrator import RunResult, run_scan
from taki.schemas.models import RunMode, SecurityRule
from taki.store.models import (
    Document,
    FindingRow,
    LedgerCellRow,
    Project,
    RunManifestRow,
    ScanRun,
    SecurityRuleRow,
    VerdictRow,
)

# 로컬 개발 DB의 값이다(deploy/docker-compose.yml). 다른 DB는 TAKI_DB_URL로 넘긴다.
DEFAULT_DB_URL = os.environ.get(
    "TAKI_DB_URL", "postgresql+psycopg://taki:taki-local-dev@127.0.0.1:55432/taki"
)
MIGRATIONS = Path(__file__).parent / "migrations"


def upgrade_database(url: str = DEFAULT_DB_URL) -> None:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(config, "head")


def make_session_factory(url: str = DEFAULT_DB_URL) -> sessionmaker[Session]:
    return sessionmaker(create_engine(url, pool_pre_ping=True), expire_on_commit=False)


def claim_next(session: Session) -> ScanRun | None:
    """대기 중인 작업 하나를 잠그고 running으로 바꾼다. 다른 worker가 잠근 작업은 건너뛴다."""
    query = select(ScanRun).where(ScanRun.status == "queued").order_by(ScanRun.id).with_for_update(skip_locked=True).limit(1)
    run = session.scalars(query).first()
    if run is not None:
        run.status = "running"
        session.flush()
    return run


def approved_rules(session: Session, project_id: int) -> list[SecurityRule]:
    rows = session.scalars(select(SecurityRuleRow).where(SecurityRuleRow.project_id == project_id,
                                                         SecurityRuleRow.status == "approved"))
    return [SecurityRule.model_validate(r.data) for r in rows]


def _save_result(session: Session, run: ScanRun, result: RunResult) -> None:
    for verdict in result.verdicts:
        session.add(VerdictRow(scan_id=run.id, case_id=verdict.case_id, state=verdict.state.value,
                               data=verdict.model_dump(mode="json")))
    for finding in result.findings:
        session.add(FindingRow(scan_id=run.id, finding_id=finding.finding_id, state=finding.state.value,
                               data=finding.model_dump(mode="json")))
    for cell in result.ledger:
        session.add(LedgerCellRow(scan_id=run.id, subject=cell.subject, target=cell.target, state=cell.state.value,
                                  reason=cell.reason))
    manifest = Path(result.out) / "manifest.jsonl"
    for line in manifest.read_text(encoding="utf-8").splitlines() if manifest.exists() else []:
        entry = json.loads(line)
        entry.pop("messages", None)  # 프롬프트 전문은 실행 폴더에만 둔다.
        session.add(RunManifestRow(scan_id=run.id, manifest_id=entry["manifest_id"], data=entry))


def run_next(session_factory, config: AgentConfig, runs_dir: Path) -> ScanRun | None:
    """대기 작업 하나를 돌린다. 없으면 None이다."""
    with session_factory() as session:
        run = claim_next(session)
        if run is None:
            session.commit()
            return None
        out = Path(runs_dir) / f"scan-{run.id}"
        run.out_dir = str(out)
        project = session.get(Project, run.project_id)
        target = project.target_path
        design = list(session.scalars(select(Document.path).where(Document.project_id == run.project_id)))
        rules = approved_rules(session, run.project_id)
        previous = session.get(ScanRun, run.previous_scan_id) if run.previous_scan_id else None
        previous_dir = previous.out_dir if previous else None
        session.commit()
        run_id = run.id

    outcome: RunResult | None = None
    error: str | None = None
    try:
        outcome = run_scan(target, design=[Path(d) for d in design], out=out, config=config, rules=rules,
                           mode=RunMode.recheck if previous_dir else RunMode.full,
                           previous=Path(previous_dir) if previous_dir else None)
    except Exception as e:  # noqa: BLE001 - 어떤 실패든 작업이 running으로 남아 멈추면 안 된다.
        error = f"{type(e).__name__}: {e}"

    with session_factory() as session:
        run = session.get(ScanRun, run_id)
        run.finished_at = datetime.now(UTC)
        if outcome is not None:
            run.exit_code = outcome.exit_code
            run.error = outcome.error
            run.status = "failed" if outcome.exit_code == 3 else "done"
            _save_result(session, run, outcome)
        else:
            run.status, run.exit_code, run.error = "failed", 3, error
        session.commit()
        return run
