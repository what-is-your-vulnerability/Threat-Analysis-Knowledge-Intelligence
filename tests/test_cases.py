from pathlib import Path

from agent.llm.roles import InvestigateResult
from agent.schemas.models import (
    Budget,
    CaseSource,
    Disposition,
    Fact,
    Flow,
    LedgerState,
    LensDisposition,
    RuleStatus,
    SecurityRule,
    Slice,
    SliceFile,
    VerdictState,
)
from agent.steps.cases import build_cases, pass_through_alerts, update_ledger
from agent.steps.lenses import load_lenses
from agent.steps.scope import scan_scope
from agent.steps.slices import load_slices, render_slice

FIX = Path(__file__).parent / "fixtures" / "spring-members"


def _rule(**kw):
    values = {"rule_id": "R1", "title": "삭제는 관리자만", "status": RuleStatus.approved,
              "applies_to": ["DELETE /api/members/*"]}
    return SecurityRule(**{**values, **kw})


def _slice():
    return Slice(slice_id="s", name="members", flows=[
        Flow(flow_id="DELETE /api/members/{id}", method="DELETE", path="/api/members/{id}"),
        Flow(flow_id="DELETE /api/members/{id}/photo", method="DELETE", path="/api/members/{id}/photo"),
        Flow(flow_id="GET /api/members", method="GET", path="/api/members"),
    ])


def test_rule_case_per_matching_flow():
    cases = build_cases([_slice()], [_rule()], Budget())
    assert [c.flow_id for c in cases] == ["DELETE /api/members/{id}", "DELETE /api/members/{id}/photo"]
    assert len({c.case_id for c in cases}) == 2 and cases[0].subject_id == "R1"


def test_pending_rule_makes_no_case():
    assert build_cases([_slice()], [_rule(status=RuleStatus.pending)], Budget()) == []


def test_rule_matching_no_flow_makes_no_case():
    assert build_cases([_slice()], [_rule(applies_to=["PUT /x"])], Budget()) == []


def test_update_ledger_records_error():
    case = build_cases([_slice()], [_rule()], Budget())[0]
    ledger = []
    update_ledger(ledger, case, None, error="호출 실패")
    assert ledger[0].state == LedgerState.not_seen and ledger[0].reason == "호출 실패"


def test_load_slices_keeps_flows_and_table():
    snap = scan_scope(FIX / "vulnerable")
    s = load_slices(FIX / "slices.yml", snap)[0]
    assert s.name == "admin-members" and s.flows[2].flow_id == "DELETE /api/v1/admin/members/{id}"
    assert s.flows[2].middleware_complete and s.requirement_refs == ["design.md#회원 관리 API"]
    assert s.sibling_table[0]["guards"] == ["authenticated", "hasRole('ADMIN')"] and s.code_hash


def test_missing_flows_default_to_incomplete(tmp_path):
    (tmp_path / "a.java").write_text("class A {}\n")
    (tmp_path / "s.yml").write_text("- name: x\n  files: [{path: a.java}]\n  flows: [{method: GET, path: /x}]\n")
    assert not load_slices(tmp_path / "s.yml", scan_scope(tmp_path))[0].flows[0].middleware_complete


def test_missing_file_is_recorded_not_dropped(tmp_path):
    (tmp_path / "a.java").write_text("class A {}\n")
    (tmp_path / "s.yml").write_text("- name: x\n  files: [{path: a.java}, {path: gone.java}]\n")
    s = load_slices(tmp_path / "s.yml", scan_scope(tmp_path))[0]
    assert "gone.java" in s.truncated[0] and [f.path for f in s.files] == ["a.java"]
    assert s.capability.value == "partial"


def test_grep_limits_to_matching_lines(tmp_path):
    body = "\n".join(f"line{i}" for i in range(1, 101)) + "\n"
    (tmp_path / "a.ts").write_text(body)
    (tmp_path / "s.yml").write_text("- name: x\n  files: [{path: a.ts, grep: line50}]\n")
    snap = scan_scope(tmp_path)
    s = load_slices(tmp_path / "s.yml", snap)[0]
    text = render_slice(s, snap)
    assert "   50| line50" in text and "line1\n" not in text and "line100" not in text


def test_render_slice_keeps_line_numbers():
    snap = scan_scope(FIX / "vulnerable")
    text = render_slice(load_slices(FIX / "slices.yml", snap)[0], snap)
    assert "=== FILE src/main/java/demo/member/MemberController.java ===" in text
    assert "   35|     public void delete(@PathVariable long id) {" in text
    assert "DELETE /api/v1/admin/members/{id}" in text


def _alert(cwe="CWE-89", file="A.java", line=3, rule="sql-rule"):
    return Fact(kind="alert", file=file, line=line, tool="semgrep",
                detail={"cwe": cwe, "rule": rule, "message": "경고 내용"})


def _question_case():
    return build_cases([Slice(slice_id="s", name="s")], [], Budget(), lenses=load_lenses())[0]


def test_missing_disposition_is_not_seen():
    ledger = []
    result = InvestigateResult(dispositions=[LensDisposition(lens_id="L1", disposition=Disposition.no_issue)])
    update_ledger(ledger, _question_case(), result, lenses=load_lenses())
    states = {c.subject: c.state for c in ledger}
    assert len(ledger) == 11 and states["L1"] == LedgerState.checked and states["L8"] == LedgerState.not_seen


def test_no_issue_is_recorded_as_not_found():
    ledger = []
    result = InvestigateResult(dispositions=[LensDisposition(lens_id="L1", disposition=Disposition.no_issue)])
    update_ledger(ledger, _question_case(), result, lenses=load_lenses()[:1])
    assert ledger[0].reason == "이상을 찾지 못함"


def test_issue_without_claim_is_not_seen():
    ledger = []
    result = InvestigateResult(dispositions=[LensDisposition(lens_id="L1", disposition=Disposition.issue)])
    update_ledger(ledger, _question_case(), result, lenses=load_lenses()[:1])
    assert ledger[0].state == LedgerState.not_seen


def test_alert_in_scope_makes_case():
    slices = [Slice(slice_id="s", name="s", files=[SliceFile(path="A.java")])]
    case = build_cases(slices, [], Budget(), alerts=[_alert()])[0]
    assert case.source == CaseSource.alert and case.slice_id == "s" and "경고 내용" in case.question
    assert case.subject_id == "sql-rule"


def test_alert_id_ignores_line_number():
    slices = [Slice(slice_id="s", name="s", files=[SliceFile(path="A.java")])]
    first = build_cases(slices, [], Budget(), alerts=[_alert(line=3)])[0]
    second = build_cases(slices, [], Budget(), alerts=[_alert(line=9)])[0]
    assert first.case_id == second.case_id


def test_out_of_scope_alert_makes_no_case_and_passes_through():
    slices = [Slice(slice_id="s", name="s", files=[SliceFile(path="A.java")])]
    ssrf = _alert(cwe="CWE-918", rule="ssrf-rule")
    assert build_cases(slices, [], Budget(), alerts=[ssrf]) == []
    finding = pass_through_alerts([ssrf], slices)[0]
    assert finding.state == VerdictState.unverified and finding.tool_confirmed and finding.root_file == "A.java"
    assert finding.statement == "경고 내용" and finding.cwe == "CWE-918"


def test_in_scope_alert_outside_slices_passes_through():
    slices = [Slice(slice_id="s", name="s", files=[SliceFile(path="B.java")])]
    alert = _alert()
    assert build_cases(slices, [], Budget(), alerts=[alert]) == []
    assert pass_through_alerts([alert], slices)[0].root_file == "A.java"


def test_in_scope_alert_inside_slice_is_not_passed_through():
    slices = [Slice(slice_id="s", name="s", files=[SliceFile(path="A.java")])]
    assert pass_through_alerts([_alert()], slices) == []
