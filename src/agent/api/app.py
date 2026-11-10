"""로컬 API. 인증이 없으므로 개발 PC의 주소에만 바인딩한다. 검사는 worker가 돌리고 API는 대기열에 넣기만 한다."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select

from agent.adapters.lang.java_index import build_index
from agent.adapters.lang.spring import extract_spring
from agent.adapters.repo.local import ForbiddenPathError, check_allowed
from agent.config import AgentConfig, ConfigError
from agent.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from agent.llm.roles import derive_rules, load_templates, renumber_after
from agent.steps.scope import scan_scope
from agent.store.models import Document, FindingRow, LedgerCellRow, Project, ScanRun, SecurityRuleRow

API_HOST = "127.0.0.1"
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
GATE_OUTCOME = {0: "pass", 1: "warn", 2: "block", 3: "failed"}


class ProjectIn(BaseModel):
    name: str
    target_path: str


class DocumentIn(BaseModel):
    path: str


class ScanIn(BaseModel):
    project_id: int
    previous_scan_id: int | None = None


class GateIn(BaseModel):
    scan_id: int


def _allowed(path: str) -> None:
    try:
        check_allowed(Path(path).resolve())
    except ForbiddenPathError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _rule_out(row: SecurityRuleRow) -> dict:
    return {"id": row.id, "rule_id": row.rule_id, "status": row.status, "version": row.version, "data": row.data}


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _scan_out(run: ScanRun, project: Project) -> dict:
    return {"id": run.id, "project_id": run.project_id, "project_name": project.name, "status": run.status,
            "exit_code": run.exit_code, "error": run.error, "previous_scan_id": run.previous_scan_id,
            "created_at": _iso(run.created_at), "finished_at": _iso(run.finished_at)}


def create_app(session_factory, config: AgentConfig, *, runs_dir: Path = Path("runs")) -> FastAPI:
    app = FastAPI(title="보안 진단 Agent API", version="0.1.0")
    # 인증이 없으므로 DNS rebinding으로 들어온 요청을 거절한다.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))

    @app.middleware("http")
    async def require_json(request: Request, call_next):
        # 다른 웹 페이지의 form 전송으로 승인·도출 같은 상태 변경이 일어나지 않게 JSON 요청만 받는다.
        content_type = request.headers.get("content-type", "")
        if request.method in STATE_CHANGING and not content_type.startswith("application/json"):
            return JSONResponse(status_code=415, content={"detail": "JSON 본문이 필요합니다."})
        return await call_next(request)

    prefix = "/api/v1"

    def _get(session, model, item_id: int):
        item = session.get(model, item_id)
        if item is None:
            raise HTTPException(status_code=404, detail=f"{model.__tablename__} {item_id} 없음")
        return item

    @app.post(f"{prefix}/projects", status_code=201)
    def create_project(body: ProjectIn) -> dict:
        _allowed(body.target_path)
        with session_factory() as session:
            project = Project(name=body.name, target_path=body.target_path)
            session.add(project)
            session.commit()
            return {"id": project.id, "name": project.name, "target_path": project.target_path}

    @app.post(f"{prefix}/projects/{{project_id}}/documents", status_code=201)
    def add_document(project_id: int, body: DocumentIn) -> dict:
        _allowed(body.path)
        with session_factory() as session:
            _get(session, Project, project_id)
            document = Document(project_id=project_id, path=body.path)
            session.add(document)
            session.commit()
            return {"id": document.id, "path": document.path}

    @app.post(f"{prefix}/projects/{{project_id}}/rules/derive")
    def derive(project_id: int) -> dict:
        with session_factory() as session:
            project = _get(session, Project, project_id)
            paths = list(session.scalars(select(Document.path).where(Document.project_id == project_id)))
            if not paths:
                raise HTTPException(status_code=400, detail="설계문서가 없습니다.")
            snapshot = scan_scope(Path(project.target_path))
            spring = extract_spring(snapshot, build_index(snapshot))
            entrypoints = [f"{e.method} {e.path_template}" for e in spring.entrypoints]
            try:
                derived = derive_rules(paths, entrypoints, load_templates(),
                                       gateway=LlmGateway(config, Path(runs_dir) / f"derive-{project_id}"))
            except ConfigError as e:
                raise HTTPException(status_code=409, detail=str(e)) from e
            except (LlmCallError, LlmFormatError, BudgetExceeded, SecretLeft) as e:
                raise HTTPException(status_code=502, detail=str(e)) from e
            existing = list(session.scalars(select(SecurityRuleRow).where(SecurityRuleRow.project_id == project_id)))
            # 승인 전 후보만 새 후보로 바꾸고, ID는 이 프로젝트에서 쓴 적 없는 번호로 매긴다.
            for row in existing:
                if row.status != "approved":
                    session.delete(row)
            fresh = renumber_after([r.rule_id for r in existing], list(derived))
            rows = [SecurityRuleRow(project_id=project_id, rule_id=r.rule_id, status=r.status.value, version=r.version,
                                    data=r.model_dump(mode="json")) for r in fresh]
            session.add_all(rows)
            session.commit()
            return {"rules": [_rule_out(r) for r in rows], "warnings": derived.warnings}

    @app.get(f"{prefix}/projects/{{project_id}}/rules")
    def list_rules(project_id: int) -> list[dict]:
        with session_factory() as session:
            rows = session.scalars(select(SecurityRuleRow).where(SecurityRuleRow.project_id == project_id).order_by(SecurityRuleRow.id))
            return [_rule_out(r) for r in rows]

    @app.post(f"{prefix}/rules/{{rule_id}}/approve")
    def approve(rule_id: int) -> dict:
        with session_factory() as session:
            row = _get(session, SecurityRuleRow, rule_id)
            if row.status != "approved":
                row.status = "approved"
                row.version += 1
                row.data = {**row.data, "status": "approved", "version": row.version}
                session.commit()
            return _rule_out(row)

    @app.post(f"{prefix}/scans", status_code=202)
    def create_scan(body: ScanIn) -> dict:
        with session_factory() as session:
            project = _get(session, Project, body.project_id)
            if body.previous_scan_id is not None:
                _get(session, ScanRun, body.previous_scan_id)
            run = ScanRun(project_id=body.project_id, status="queued", previous_scan_id=body.previous_scan_id)
            session.add(run)
            session.commit()
            return _scan_out(run, project)

    @app.get(f"{prefix}/scans/{{scan_id}}")
    def get_scan(scan_id: int) -> dict:
        with session_factory() as session:
            run = _get(session, ScanRun, scan_id)
            return _scan_out(run, session.get(Project, run.project_id))

    @app.get(f"{prefix}/scans/{{scan_id}}/findings")
    def get_findings(scan_id: int) -> list[dict]:
        with session_factory() as session:
            _get(session, ScanRun, scan_id)
            return [r.data for r in session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id).order_by(FindingRow.id))]

    @app.get(f"{prefix}/scans/{{scan_id}}/ledger")
    def get_ledger(scan_id: int) -> list[dict]:
        with session_factory() as session:
            _get(session, ScanRun, scan_id)
            rows = session.scalars(select(LedgerCellRow).where(LedgerCellRow.scan_id == scan_id).order_by(LedgerCellRow.id))
            return [{"subject": r.subject, "target": r.target, "state": r.state, "reason": r.reason} for r in rows]

    @app.get(f"{prefix}/scans/{{scan_id}}/report")
    def get_report(scan_id: int) -> dict:
        with session_factory() as session:
            run = _get(session, ScanRun, scan_id)
            path = Path(run.out_dir or "") / "report.json"
            if not run.out_dir or not path.exists():
                raise HTTPException(status_code=409, detail="리포트가 아직 없습니다.")
            return {"project_name": session.get(Project, run.project_id).name,
                    **json.loads(path.read_text(encoding="utf-8"))}

    @app.post(f"{prefix}/gates/evaluate")
    def evaluate_gate(body: GateIn) -> dict:
        with session_factory() as session:
            run = _get(session, ScanRun, body.scan_id)
            if run.status in ("queued", "running"):
                raise HTTPException(status_code=409, detail="검사가 끝나지 않았습니다.")
            return {"scan_id": run.id, "outcome": GATE_OUTCOME.get(run.exit_code, "failed"), "error": run.error}

    return app
