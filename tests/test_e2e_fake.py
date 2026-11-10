import json
from pathlib import Path

import pytest
from conftest import make_config

from agent.cli.main import main
from agent.config import ConfigError
from agent.core.orchestrator import run_scan
from agent.schemas.models import CaseSource, Fact, LedgerState, RunMode, VerdictState
from agent.steps.cases import load_rules

FIX = Path(__file__).parent / "fixtures" / "spring-members"
VULN, FIXED, DESIGN, SLICES, RULES_FILE = (
    FIX / "vulnerable", FIX / "fixed", FIX / "design.md", FIX / "slices.yml", FIX / "rules.yml")
RULES = load_rules(RULES_FILE)


@pytest.fixture
def scripted(fake):
    fake.responses.extend(json.loads((FIX / "fake_script.json").read_text(encoding="utf-8")))
    return fake


def _scan(fake, out, target=VULN, **kw):
    return run_scan(target, design=[DESIGN], out=out, config=make_config(fake), slices_file=SLICES, rules=RULES, **kw)


def test_vulnerable_demo_reports_missing(scripted, tmp_path):
    r = _scan(scripted, tmp_path)
    assert r.exit_code == 1
    f = r.findings[0]
    assert f.state == VerdictState.missing_suspected and f.root_file.endswith("MemberController.java")
    assert (tmp_path / "report.json").exists() and "회원 삭제" in (tmp_path / "report.html").read_text()
    assert f.fix and "PreAuthorize" in f.fix.code_example and f.cwe == "CWE-862"
    assert (tmp_path / "results.sarif").exists() and (tmp_path / "ledger.json").exists()


def test_only_matching_flow_is_investigated(scripted, tmp_path):
    r = _scan(scripted, tmp_path)
    assert [c.flow_id for c in r.cases if c.source == CaseSource.rule] == ["DELETE /api/v1/admin/members/{id}"]
    assert [c.slice_id for c in r.cases if c.source == CaseSource.question] == ["admin-members"]


def test_fixed_demo_recheck_resolved(scripted, tmp_path):
    first = _scan(scripted, tmp_path / "before")
    r = _scan(scripted, tmp_path / "after", target=FIXED, mode=RunMode.recheck, previous=tmp_path / "before")
    assert r.exit_code == 0 and r.findings == []
    assert {i.change for i in r.recheck} == {"resolved"} and first.cases[0].case_id in {i.case_id for i in r.recheck}
    assert r.verdicts[0].state == VerdictState.implemented


def test_llm_failure_becomes_unverified(fake, tmp_path):
    r = _scan(fake, tmp_path)
    assert r.exit_code == 1 and r.verdicts[0].state == VerdictState.unverified
    cell = next(c for c in r.ledger if c.subject == "R1")
    assert cell.state == LedgerState.not_seen and cell.reason


def test_report_never_says_safe(scripted, tmp_path):
    _scan(scripted, tmp_path / "a")
    _scan(scripted, tmp_path / "b", target=FIXED)
    for d in ("a", "b"):
        assert "안전" not in (tmp_path / d / "report.html").read_text()
        assert "안전" not in (tmp_path / d / "report.json").read_text()


def test_report_escapes_code(fake, tmp_path):
    claim = {"claim": "absent", "statement": "<script>alert(1)</script>", "hops": [], "basis": ["x"],
             "expected_positions": ["y"]}
    fake.responses += [
        {"match": "재검토한다", "content": '{"result": "kept"}'},
        {"match": "수정 방법을 제안한다", "content": '{"location": "l", "code_example": "c", "check_scenario": "s"}'},
        {"match": "조사 항목 하나를", "content": json.dumps({"claims": [claim]})},
    ]
    _scan(fake, tmp_path)
    assert "<script>alert" not in (tmp_path / "report.html").read_text()


def test_report_lists_what_was_not_seen(fake, tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.bin").write_bytes(b"x")
    (tmp_path / "t" / "a.java").write_text("class A {}\n")
    r = run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=make_config(fake), slices_file=SLICES)
    html = (tmp_path / "o" / "report.html").read_text()
    assert "못 본 범위" in html and "a.bin" in html and r.exit_code == 1


def test_failed_scope_exit_3(tmp_path):
    (tmp_path / "empty").mkdir()
    r = run_scan(tmp_path / "empty", design=[], out=tmp_path / "o", config=make_config_unused())
    assert r.exit_code == 3 and (tmp_path / "o" / "report.json").exists()


def make_config_unused():
    from agent.config import AgentConfig

    return AgentConfig()


def test_missing_model_is_not_turned_into_a_finding(fake, tmp_path):
    with pytest.raises(ConfigError):
        run_scan(VULN, design=[], out=tmp_path, config=make_config(fake, models={"investigate": None}),
                 slices_file=SLICES, rules=RULES)
    assert fake.requests == []


def test_forbidden_design_path_rejected(fake, tmp_path):
    from agent.adapters.repo.local import ForbiddenPathError

    with pytest.raises(ForbiddenPathError):
        run_scan(VULN, design=[tmp_path / "ground-truth-private" / "x.md"], out=tmp_path / "o",
                 config=make_config(fake), slices_file=SLICES, rules=RULES)


def test_quote_failure_requests_once_more(fake, tmp_path):
    bad = {"claims": [{"claim": "absent", "statement": "s", "root_symbol": "MemberController.delete", "basis": ["x"],
                       "expected_positions": ["y"],
                       "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 1, "end": 1,
                                 "quote": "없는 문장", "role": "root_control"}]}]}
    fake.responses += [{"content": json.dumps(bad)}, {"content": json.dumps(bad)},
                       {"content": '{"claims": []}'}]  # 세 번째는 고정 질문 항목
    r = _scan(fake, tmp_path)
    assert len(fake.requests) == 3 and "quote_not_found" in json.dumps(fake.requests[1]["messages"], ensure_ascii=False)
    assert r.verdicts[0].state == VerdictState.unverified


def test_refuted_review_evidence_is_checked(fake, tmp_path):
    fake.responses += [
        {"match": "재검토한다", "content": json.dumps({"result": "refuted", "reason": "있다", "evidence": {
            "claim": "implemented", "statement": "s", "checked_value": "x", "used_value": "x",
            "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 1, "end": 1,
                      "quote": "지어낸 코드 x", "role": "root_control"}]}})},
        *json.loads((FIX / "fake_script.json").read_text(encoding="utf-8"))[3:],
    ]
    r = _scan(fake, tmp_path)
    assert r.verdicts[0].state == VerdictState.unverified and r.verdicts[0].evidence.claim.value == "absent"


def test_cli_scan_and_recheck(scripted, tmp_path, capsys, monkeypatch):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"base_url: {scripted.url}\nmodels: {{investigate: m, review: m, fix: m}}\n")
    common = ["--slices", str(SLICES), "--rules", str(RULES_FILE), "--config", str(cfg), "--design", str(DESIGN)]
    assert main(["scan", str(VULN), "--out", str(tmp_path / "a"), *common]) == 1
    assert main(["recheck", str(FIXED), "--previous", str(tmp_path / "a"), "--out", str(tmp_path / "b"), *common]) == 0
    assert "resolved" in capsys.readouterr().out


def test_cli_reports_missing_model_without_traceback(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # 작업 폴더의 agent.yml을 읽지 않게 한다.
    code = main(["scan", str(VULN), "--out", str(tmp_path / "a"), "--slices", str(SLICES), "--rules", str(RULES_FILE)])
    assert code == 3 and "모델" in capsys.readouterr().err


def test_all_11_questions_sent(scripted, tmp_path):
    _scan(scripted, tmp_path)
    sent = [json.dumps(r["messages"], ensure_ascii=False) for r in scripted.requests]
    question = next(t for t in sent if "lens_id별로" in t)
    assert all(lens in question for lens in ["L1", "L2a", "L2b", "L2c", "L3", "L4", "L5", "L6a", "L6b", "L7", "L8"])


def test_no_issue_is_not_implemented(fake, tmp_path):
    answer = {"claims": [], "dispositions": [{"lens_id": x, "disposition": "no_issue"} for x in (
        "L1", "L2a", "L2b", "L2c", "L3", "L4", "L5", "L6a", "L6b", "L7", "L8")]}
    fake.responses.append({"match": "lens_id별로", "content": json.dumps(answer)})
    r = run_scan(VULN, design=[], out=tmp_path, config=make_config(fake), slices_file=SLICES)
    assert r.verdicts == [] and r.exit_code == 0
    html = (tmp_path / "report.html").read_text()
    assert "구현 확인" not in html and "이상을 찾지 못함" in html


def test_missing_answer_shows_in_report(fake, tmp_path):
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'})
    r = run_scan(VULN, design=[], out=tmp_path, config=make_config(fake), slices_file=SLICES)
    assert r.exit_code == 1 and any(c.state == LedgerState.not_seen and c.subject == "L8" for c in r.ledger)
    assert "L8" in (tmp_path / "report.html").read_text()


def test_out_of_scope_alert_skips_llm(fake, tmp_path):
    answer = {"claims": [], "dispositions": []}
    fake.responses.append({"match": "lens_id별로", "content": json.dumps(answer)})
    alert = Fact(kind="alert", file="src/main/java/demo/member/MemberService.java", line=3, tool="semgrep",
                 detail={"cwe": "CWE-918", "rule": "ssrf", "message": "SSRF 위험 원문"})
    r = run_scan(VULN, design=[], out=tmp_path, config=make_config(fake), slices_file=SLICES, alerts=[alert])
    assert not any("SSRF 위험 원문" in json.dumps(q, ensure_ascii=False) for q in fake.requests)
    assert "SSRF 위험 원문" in (tmp_path / "report.html").read_text() and r.findings[0].tool_confirmed
    assert r.exit_code == 1


def test_sibling_guard_cannot_refute_missing(fake, tmp_path):
    # 재검토가 형제 API(suspend)의 @PreAuthorize를 delete의 기각 근거로 내도 누락이 구현 확인으로 바뀌면 안 된다.
    sibling = {"claim": "implemented", "statement": "관리자 확인이 있다", "checked_value": "hasRole('ADMIN')",
               "used_value": "hasRole('ADMIN')", "root_symbol": "MemberController.delete",
               "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 28, "end": 37,
                         "quote": "@PreAuthorize(\"hasRole('ADMIN')\")\n    public void suspend(@PathVariable long id) {",
                         "role": "root_control"}]}
    fake.responses += [
        {"match": "재검토한다", "content": json.dumps({"result": "refuted", "reason": "있다", "evidence": sibling})},
        *json.loads((FIX / "fake_script.json").read_text(encoding="utf-8"))[2:],
    ]
    r = _scan(fake, tmp_path)
    rule_verdicts = [v for v in r.verdicts if v.case_id == r.cases[0].case_id]
    assert rule_verdicts[0].state != VerdictState.implemented and r.exit_code == 1


def test_unexpected_error_exits_3(tmp_path, capsys, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("예상 못 한 오류")

    monkeypatch.setattr("agent.cli.main.run_scan", broken)
    code = main(["scan", str(VULN), "--out", str(tmp_path / "a"), "--slices", str(SLICES)])
    assert code == 3 and "예상 못 한 오류" in capsys.readouterr().err


def test_all_llm_failures_are_not_shown_as_zero_issues(fake, tmp_path):
    r = _scan(fake, tmp_path)  # 모의 LLM이 응답을 주지 않아 모든 호출이 실패한다
    html = (tmp_path / "report.html").read_text()
    assert r.findings and all(f.state == VerdictState.unverified for f in r.findings)
    assert "보고할 이슈가 없습니다" not in html and "이슈 0건" not in html


def test_failed_alert_investigation_keeps_the_scanner_finding(fake, tmp_path):
    alert = Fact(kind="alert", file="src/main/java/demo/member/MemberService.java", line=22, tool="semgrep",
                 detail={"cwe": "CWE-89", "rule": "sql", "message": "SQL 조립 경고 원문"})
    r = run_scan(VULN, design=[], out=tmp_path, config=make_config(fake), slices_file=SLICES, alerts=[alert])
    assert any(f.tool_confirmed and f.statement == "SQL 조립 경고 원문" for f in r.findings)


def test_out_inside_target_is_not_analyzed(scripted, tmp_path):
    import shutil

    target = tmp_path / "app"
    shutil.copytree(VULN, target)
    first = run_scan(target, design=[DESIGN], out=target / "runs" / "a", config=make_config(scripted),
                     slices_file=SLICES, rules=RULES)
    assert not any(f.path.startswith("runs/") for f in first.snapshot.files)
    second = run_scan(target, design=[DESIGN], out=target / "runs" / "b", config=make_config(scripted),
                      slices_file=SLICES, rules=RULES)
    assert not any(f.path.startswith("runs/") for f in second.snapshot.files)
    assert {"runs/a", "runs/b"} <= {n.path for n in second.snapshot.not_read}


QUESTION_CLAIM = {"claim": "absent", "statement": "삭제에 관리자 확인이 없다", "cwe": "CWE-862", "category": 2,
                  "root_symbol": "MemberController.delete", "expected_positions": ["MemberController.delete"],
                  "basis": ["MemberController.suspend의 hasRole"],
                  "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 35, "end": 35,
                            "quote": "public void delete(@PathVariable long id) {", "role": "root_control"}]}
FIXED_PROOF = {"claim": "implemented", "statement": "관리자 확인이 있다", "category": 2,
               "root_symbol": "MemberController.delete", "checked_value": "hasRole('ADMIN')",
               "used_value": "hasRole('ADMIN')",
               "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 36, "end": 37,
                         "quote": "@PreAuthorize(\"hasRole('ADMIN')\")\n    public void delete(@PathVariable long id) {",
                         "role": "root_control"}]}


def test_question_issue_fixed_is_resolved_on_recheck(fake, tmp_path):
    fake.responses += [{"match": "재검토한다", "content": '{"result": "kept"}'},
                       {"match": "수정 방법을 제안한다", "content": '{"location": "l", "code_example": "c", "check_scenario": "s"}'}]
    fake.responses.append({"match": "lens_id별로", "content": json.dumps({"claims": [QUESTION_CLAIM]})})
    before = run_scan(VULN, design=[], out=tmp_path / "a", config=make_config(fake), slices_file=SLICES)
    assert before.findings[0].state == VerdictState.missing_suspected
    fake.responses[:] = [{"match": "이전 검사의 주장", "content": json.dumps({"claims": [FIXED_PROOF]})},
                         {"match": "lens_id별로", "content": '{"claims": []}'}]
    after = run_scan(FIXED, design=[], out=tmp_path / "b", config=make_config(fake), slices_file=SLICES,
                     mode=RunMode.recheck, previous=tmp_path / "a")
    assert {i.change for i in after.recheck} == {"resolved"}


def test_no_scanner_is_recorded_in_scan(fake, tmp_path):
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    r = run_scan(VULN, design=[], out=tmp_path, config=make_config(fake), slices_file=SLICES)
    assert any(c.subject == "scanner:*" and c.state == LedgerState.deferred for c in r.ledger)


def test_report_has_capability_table_and_partial_status(fake, tmp_path):
    import shutil

    target = tmp_path / "app"
    shutil.copytree(VULN, target)
    (target / "web").mkdir()
    (target / "web" / "app.js").write_text("fetch('/api/v1/admin/members')\n")
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    run_scan(target, design=[], out=tmp_path / "o", config=make_config(fake))
    report = json.loads((tmp_path / "o" / "report.json").read_text())
    assert report["capabilities"]["spring.entrypoints"] == "supported"
    assert any(c["state"] == "not_seen" and "web/app.js" in c["reason"] for c in report["ledger"])
    assert "분석 범위" in (tmp_path / "o" / "report.html").read_text()


def test_unknown_framework_makes_status_partial(fake, tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.mjs").write_text("export const a = 1;\n")
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=make_config(fake))
    assert json.loads((tmp_path / "o" / "report.json").read_text())["status"] == "partial"
