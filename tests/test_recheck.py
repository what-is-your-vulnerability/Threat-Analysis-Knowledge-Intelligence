import json

from agent.steps.recheck import compare_runs


def _verdict(case_id, state, key="k1", code_hash="h", file="A.java"):
    evidence = {"hops": [{"file": file}]} if state != "none" else None
    return {"case_id": case_id, "claim_key": key, "state": state, "code_hash": code_hash, "evidence": evidence}


def _report(path, verdicts, files=("A.java",)):
    path.mkdir(parents=True, exist_ok=True)
    (path / "report.json").write_text(json.dumps({"verdicts": verdicts, "files": list(files)}), encoding="utf-8")
    return path


def _changes(tmp_path, before, after, files=("A.java",)):
    items = compare_runs(_report(tmp_path / "a", before), _report(tmp_path / "b", after, files))
    return {(i.case_id, i.claim_key): i.change for i in items}


def test_fixed_is_resolved(tmp_path):
    assert _changes(tmp_path, [_verdict("c", "missing_suspected")], [_verdict("c", "implemented", code_hash="h2")]) == {
        ("c", "k1"): "resolved"}


def test_still_missing(tmp_path):
    changes = _changes(tmp_path, [_verdict("c", "missing_suspected")], [_verdict("c", "missing_suspected")])
    assert changes == {("c", "k1"): "still"}


def test_new_problem(tmp_path):
    assert _changes(tmp_path, [], [_verdict("c", "missing_suspected")]) == {("c", "k1"): "new"}


def test_removed_file_is_not_resolved(tmp_path):
    changes = _changes(tmp_path, [_verdict("c", "missing_suspected")], [_verdict("c", "implemented", code_hash="h2")],
                       files=("B.java",))
    assert changes == {("c", "k1"): "unverifiable"}


def test_removed_case_is_not_resolved(tmp_path):
    assert _changes(tmp_path, [_verdict("c", "missing_suspected")], []) == {("c", "k1"): "unverifiable"}


def test_unverified_now_is_not_resolved(tmp_path):
    changes = _changes(tmp_path, [_verdict("c", "missing_suspected")], [_verdict("c", "unverified", code_hash="h2")])
    assert changes == {("c", "k1"): "unverifiable"}


def test_same_code_changed_verdict_is_unstable(tmp_path):
    assert _changes(tmp_path, [_verdict("c", "missing_suspected")], [_verdict("c", "implemented")]) == {
        ("c", "k1"): "unstable"}


def test_two_claims_in_one_case_tracked_separately(tmp_path):
    before = [_verdict("c", "missing_suspected", "k1"), _verdict("c", "missing_suspected", "k2")]
    after = [_verdict("c", "implemented", "k1", "h2"), _verdict("c", "missing_suspected", "k2", "h2")]
    assert _changes(tmp_path, before, after) == {("c", "k1"): "resolved", ("c", "k2"): "still"}


def test_renamed_claim_in_failing_case_is_still(tmp_path):
    after = [_verdict("c", "missing_suspected", "other", "h2")]
    assert _changes(tmp_path, [_verdict("c", "missing_suspected")], after)[("c", "k1")] == "still"


def test_implemented_before_and_after_is_not_listed(tmp_path):
    assert _changes(tmp_path, [_verdict("c", "implemented")], [_verdict("c", "implemented")]) == {}


def test_regression_is_new(tmp_path):
    after = [_verdict("c", "missing_suspected", code_hash="h2")]
    assert _changes(tmp_path, [_verdict("c", "implemented")], after) == {("c", "k1"): "new"}


def test_extra_claim_in_same_case_is_new(tmp_path):
    after = [_verdict("c", "missing_suspected", "k1", "h2"), _verdict("c", "missing_suspected", "k2", "h2")]
    assert _changes(tmp_path, [_verdict("c", "missing_suspected", "k1")], after) == {
        ("c", "k1"): "still", ("c", "k2"): "new"}


def _report_with(path, verdicts=(), findings=(), ledger=(), files=("A.java",)):
    path.mkdir(parents=True, exist_ok=True)
    data = {"verdicts": list(verdicts), "findings": list(findings), "ledger": list(ledger), "files": list(files)}
    (path / "report.json").write_text(json.dumps(data), encoding="utf-8")
    return path


SCANNER_FINDING = {"finding_id": "f1", "tool_confirmed": True, "case_ids": [], "state": "unverified",
                   "root_file": "A.java", "evidence": [{"basis": ["semgrep r"]}]}
RAN = {"subject": "scanner:semgrep", "target": "*", "state": "checked", "reason": "실행함"}


def test_scanner_only_issue_still_there(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    after = _report_with(tmp_path / "b", findings=[SCANNER_FINDING])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "still")]


def test_scanner_only_issue_gone_with_scanner_running_is_resolved(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    after = _report_with(tmp_path / "b", ledger=[RAN])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "resolved")]


def test_scanner_only_issue_gone_with_scanner_off_is_unverifiable(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    off = {"subject": "scanner:*", "target": "*", "state": "deferred", "reason": "등록된 스캐너 없음"}
    after = _report_with(tmp_path / "b", ledger=[off])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "unverifiable")]


def test_scanner_only_issue_gone_with_failed_scanner_is_unverifiable(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    failed = {"subject": "scanner:semgrep", "target": "*", "state": "not_seen", "reason": "Docker 없음"}
    after = _report_with(tmp_path / "b", ledger=[failed])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "unverifiable")]


def test_scanner_only_issue_gone_with_only_language_skip_is_unverifiable(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    skipped = {"subject": "scanner:semgrep", "target": "*", "state": "deferred", "reason": "대상 언어 파일 없음 (java)"}
    after = _report_with(tmp_path / "b", ledger=[skipped])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "unverifiable")]


def test_scanner_only_issue_gone_after_tool_was_removed_is_unverifiable(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    after = _report_with(tmp_path / "b", ledger=[{**RAN, "subject": "scanner:codeql"}])
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "unverifiable")]


def test_scanner_only_issue_gone_with_file_deleted_is_unverifiable(tmp_path):
    before = _report_with(tmp_path / "a", findings=[SCANNER_FINDING])
    after = _report_with(tmp_path / "b", ledger=[RAN], files=("B.java",))
    assert [(i.case_id, i.change) for i in compare_runs(before, after)] == [("f1", "unverifiable")]
