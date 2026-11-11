import json
from pathlib import Path

import pytest
import yaml
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from conftest import make_config
from fastapi.testclient import TestClient
from sqlalchemy import text

from taki.api.app import API_HOST, create_app
from taki.store.models import Base, ScanRun
from taki.store.repo import DEFAULT_DB_URL, claim_next, make_session_factory, run_next, upgrade_database

pytestmark = pytest.mark.postgres
FIX = Path(__file__).parent / "fixtures" / "spring-members"
VULN = FIX / "vulnerable"
DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "docker-compose.yml"
QUOTE = "회원 삭제는 관리자 권한이 있어야 한다."
DERIVED = {"rules": [{"title": "회원 삭제 권한", "requirement_quote": QUOTE, "doc_ref": "design.md#회원 관리 API", "category": 2,
                      "cwe": "CWE-862", "applies_to": ["DELETE /api/v1/admin/members/*"]}],
           "category_notes": [{"category": c, "reason": "없음"} for c in (1, 3, 4, 5, 6, 7, 8)]}


@pytest.fixture(scope="module")
def sessions():
    upgrade_database(DEFAULT_DB_URL)
    return make_session_factory(DEFAULT_DB_URL)


@pytest.fixture(autouse=True)
def _empty_tables(sessions):
    with sessions() as session:
        names = ", ".join(t.name for t in Base.metadata.sorted_tables)
        session.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        session.commit()


@pytest.fixture
def scripted(fake):
    fake.responses.extend(json.loads((FIX / "fake_script.json").read_text(encoding="utf-8")))
    return fake


@pytest.fixture
def client(sessions, fake, tmp_path):
    return TestClient(create_app(sessions, make_config(fake), runs_dir=tmp_path), base_url="http://127.0.0.1")


def _project(client, target=VULN):
    response = client.post("/api/v1/projects", json={"name": "demo", "target_path": str(target)})
    assert response.status_code == 201
    return response.json()["id"]


def _scan(client, project_id, **extra):
    response = client.post("/api/v1/scans", json={"project_id": project_id, **extra})
    assert response.status_code == 202
    return response.json()


def _approved_rule(client, project_id, fake):
    assert client.post(f"/api/v1/projects/{project_id}/documents", json={"path": str(FIX / "design.md")}).status_code == 201
    fake.responses.insert(0, {"match": "보안 설계 검토자", "content": json.dumps(DERIVED, ensure_ascii=False)})
    rules = client.post(f"/api/v1/projects/{project_id}/rules/derive", json={}).json()["rules"]
    assert [r["status"] for r in rules] == ["pending"]
    return rules[0]["id"]


def test_migration_matches_models(sessions):
    with sessions() as session:
        context = MigrationContext.configure(session.connection())
        assert compare_metadata(context, Base.metadata) == []


def test_post_scan_returns_immediately_and_queues(client):
    scan = _scan(client, _project(client))
    assert scan["status"] == "queued"
    assert client.get(f"/api/v1/scans/{scan['id']}").json()["status"] == "queued"


def test_unknown_project_is_404(client):
    assert client.post("/api/v1/scans", json={"project_id": 999}).status_code == 404
    assert client.get("/api/v1/scans/999").status_code == 404


def test_forbidden_target_rejected(client, tmp_path):
    target = tmp_path / "ground-truth-private"
    target.mkdir()
    assert client.post("/api/v1/projects", json={"name": "x", "target_path": str(target)}).status_code == 400
    project_id = _project(client)
    answer = client.post(f"/api/v1/projects/{project_id}/documents", json={"path": str(target / "a.md")})
    assert answer.status_code == 400


def test_worker_runs_job_then_findings_visible(client, sessions, scripted, tmp_path):
    project_id = _project(client)
    rule_id = _approved_rule(client, project_id, scripted)
    assert client.post(f"/api/v1/rules/{rule_id}/approve", json={}).status_code == 200
    scan = _scan(client, project_id)
    assert run_next(sessions, make_config(scripted), tmp_path).id == scan["id"]
    done = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert done["status"] == "done" and done["exit_code"] == 1
    assert done["project_name"] == "demo" and done["created_at"] and done["finished_at"]
    findings =client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert findings[0]["root_symbol"] == "MemberController.delete" and findings[0]["state"] == "missing_suspected"
    assert findings[0]["fix"]["check_scenario"]
    ledger = client.get(f"/api/v1/scans/{scan['id']}/ledger").json()
    assert any(c["subject"] == "R1" and c["state"] == "checked" for c in ledger)
    report = client.get(f"/api/v1/scans/{scan['id']}/report").json()
    assert report["exit_code"] == 1 and report["findings"]
    assert report["project_name"] == "demo" and report["target"] == VULN.name
    summary = report["summary"]
    assert sum(summary["verdicts"].values()) == len(report["verdicts"])
    assert summary["findings"]["missing_suspected"] == sum(f["state"] == "missing_suspected" for f in findings)
    assert summary["findings"]["implemented"] == 0


def test_no_job_returns_none(sessions, fake, tmp_path):
    assert run_next(sessions, make_config(fake), tmp_path) is None


def test_two_workers_do_not_claim_same_job(client, sessions):
    project_id = _project(client)
    first_id = _scan(client, project_id)["id"]
    second_id = _scan(client, project_id)["id"]
    with sessions() as one, sessions() as two, sessions() as three:
        first = claim_next(one)  # 아직 커밋하지 않아 잠금을 쥐고 있다.
        second = claim_next(two)
        assert first.id == first_id and second.id == second_id
        assert claim_next(three) is None


def test_failed_job_is_failed_not_empty(client, sessions, fake, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    scan = _scan(client, _project(client, empty))
    run_next(sessions, make_config(fake), tmp_path)
    done = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert done["status"] == "failed" and done["error"] and done["exit_code"] == 3
    answer = client.post("/api/v1/gates/evaluate", json={"scan_id": scan["id"]}).json()
    assert answer["outcome"] == "failed"


def test_worker_records_unexpected_error(client, sessions, fake, tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("예상 못 한 오류")

    monkeypatch.setattr("taki.store.repo.run_scan", broken)
    scan = _scan(client, _project(client))
    run_next(sessions, make_config(fake), tmp_path)
    done = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert done["status"] == "failed" and "예상 못 한 오류" in done["error"]


def test_missing_model_fails_job_without_request(client, sessions, fake, tmp_path):
    scan = _scan(client, _project(client))
    run_next(sessions, make_config(fake, models={"investigate": None}), tmp_path)
    done = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert done["status"] == "failed" and "모델" in done["error"] and fake.requests == []


def test_gate_evaluate_warn_for_ai_only(client, sessions, scripted, tmp_path):
    scan = _scan(client, _project(client))
    answer = client.post("/api/v1/gates/evaluate", json={"scan_id": scan["id"]})
    assert answer.status_code == 409  # 아직 끝나지 않음
    run_next(sessions, make_config(scripted), tmp_path)
    assert client.post("/api/v1/gates/evaluate", json={"scan_id": scan["id"]}).json()["outcome"] == "warn"


def test_pending_rule_is_not_used(client, sessions, scripted, tmp_path):
    project_id = _project(client)
    _approved_rule(client, project_id, scripted)
    scan = _scan(client, project_id)
    run_next(sessions, make_config(scripted), tmp_path)
    report = client.get(f"/api/v1/scans/{scan['id']}/report").json()
    assert not any(c["source"] == "rule" for c in report["cases"])


def test_rule_approve_then_used(client, sessions, scripted, tmp_path):
    project_id = _project(client)
    rule_id = _approved_rule(client, project_id, scripted)
    approved = client.post(f"/api/v1/rules/{rule_id}/approve", json={}).json()
    assert approved["status"] == "approved" and approved["version"] == 2
    assert client.get(f"/api/v1/projects/{project_id}/rules").json()[0]["status"] == "approved"
    scan = _scan(client, project_id)
    run_next(sessions, make_config(scripted), tmp_path)
    report = client.get(f"/api/v1/scans/{scan['id']}/report").json()
    assert any(c["source"] == "rule" and c["subject_id"] == "R1" for c in report["cases"])


def test_recheck_compares_with_previous_scan(client, sessions, scripted, tmp_path):
    first = _scan(client, _project(client))
    run_next(sessions, make_config(scripted), tmp_path)
    fixed = _project(client, FIX / "fixed")
    second = _scan(client, fixed, previous_scan_id=first["id"])
    run_next(sessions, make_config(scripted), tmp_path)
    report = client.get(f"/api/v1/scans/{second['id']}/report").json()
    assert report["mode"] == "recheck" and {i["change"] for i in report["recheck"]} == {"resolved"}


def test_api_binds_localhost_only():
    assert API_HOST == "127.0.0.1"
    compose = yaml.safe_load(DEPLOY.read_text(encoding="utf-8"))
    assert all(p.startswith("127.0.0.1:") for p in compose["services"]["postgres"]["ports"])


def test_scan_status_column_exists():
    assert {"queued", "running", "done", "failed"} >= {ScanRun.__table__.c.status.default.arg}


def test_rejects_requests_for_other_hosts(sessions, fake, tmp_path):
    app = create_app(sessions, make_config(fake), runs_dir=tmp_path)
    assert TestClient(app, base_url="http://evil.example").get("/api/v1/scans/1").status_code == 400


def test_state_change_needs_json(client):
    project_id = _project(client)
    assert client.post(f"/api/v1/projects/{project_id}/rules/derive").status_code == 415
    form = client.post("/api/v1/rules/1/approve", data={"x": "1"})
    assert form.status_code == 415


def test_rederive_keeps_ids_unique_and_approved_rules(client, scripted):
    project_id = _project(client)
    first = _approved_rule(client, project_id, scripted)
    client.post(f"/api/v1/rules/{first}/approve", json={})
    scripted.responses.insert(0, {"match": "보안 설계 검토자", "content": json.dumps(DERIVED, ensure_ascii=False)})
    client.post(f"/api/v1/projects/{project_id}/rules/derive", json={})
    rules = client.get(f"/api/v1/projects/{project_id}/rules").json()
    assert [(r["rule_id"], r["status"]) for r in rules] == [("R1", "approved"), ("R2", "pending")]
