import json
from pathlib import Path

from agent.adapters.scanner.sarif import coverage_gaps, normalize_cwe, parse_sarif
from agent.schemas.models import Capability, Certainty, LedgerState

FIX = Path(__file__).parent / "fixtures"


def test_codeql_rules_in_extensions_give_cwe_and_flow():
    out = parse_sarif(FIX / "sarif" / "codeql.sarif", "codeql")
    a = out.alerts[0]
    assert a.tool == "codeql" and a.detail["cwe"] == "CWE-89" and a.detail["rule"] == "java/sql-injection"
    assert a.file == "src/main/java/demo/UserDao.java" and a.line == 20 and a.tool_version == "2.27.4"
    assert a.detail["flow"][0] == "src/main/java/demo/UserController.java:12" and len(a.detail["flow"]) == 3
    assert a.detail["snippet"] == ""


def test_covered_cwes_include_rules_without_results():
    assert parse_sarif(FIX / "sarif" / "codeql.sarif", "codeql").covered_cwes == {"CWE-89", "CWE-564", "CWE-22"}


def test_normalize_cwe():
    assert normalize_cwe("external/cwe/cwe-089") == "CWE-89"
    assert normalize_cwe("CWE-89: Improper Neutralization") == "CWE-89" and normalize_cwe("security") is None


def test_coverage_gaps_from_covered_set():
    cells = coverage_gaps({"CWE-22"})
    subjects = " ".join(c.subject for c in cells)
    assert "CWE-918" in subjects and "CWE-22" not in subjects and "의존성" in subjects
    assert all(c.state == LedgerState.deferred and c.reason for c in cells)


def test_parse_results_to_facts():
    outcome = parse_sarif(FIX / "semgrep" / "results.sarif", "semgrep")
    assert outcome.status == Capability.supported and outcome.errors == []
    first, second = outcome.alerts
    assert first.kind == "alert" and first.file == "app/UserDao.java" and first.line == 10 and first.tool == "semgrep"
    assert first.detail["cwe"] == "CWE-89" and first.detail["rule"] == "rules.java-string-concat-sql"
    assert first.detail["snippet"] == "statement.executeQuery(x)" and first.certainty == Certainty.tool_confirmed
    assert first.tool_version == "1.183.0" and "flow" not in first.detail
    assert second.detail["cwe"] is None and second.file == "app/A.java"
    assert outcome.covered_cwes == {"CWE-89"}


def test_rule_errors_are_partial_not_zero():
    outcome = parse_sarif(FIX / "semgrep" / "rule_error.sarif", "semgrep")
    assert outcome.status == Capability.partial and outcome.alerts == [] and "Invalid rule schema" in outcome.errors[0]


def test_missing_or_broken_sarif_is_failed(tmp_path):
    assert parse_sarif(tmp_path / "none.sarif", "semgrep").status == Capability.failed
    (tmp_path / "bad.sarif").write_text("{")
    assert parse_sarif(tmp_path / "bad.sarif", "semgrep").status == Capability.failed


def test_null_results_sarif_is_not_a_crash(tmp_path):
    rule = {"id": "r", "properties": {"tags": None, "cwe": None}}
    run = {"tool": {"driver": {"name": "t", "rules": [rule], "extensions": None}}, "invocations": None,
           "results": [{"ruleId": "r", "locations": None, "codeFlows": None, "message": None}]}
    shapes = {
        "runs-null": ({"runs": None}, Capability.failed),
        "top-array": ([{"runs": []}], Capability.failed),
        "results-null": ({"runs": [{"tool": {"driver": {"name": "t"}}, "results": None}]}, Capability.partial),
        "nulls-inside": ({"runs": [run]}, Capability.supported),
        "tool-null": ({"runs": [{"tool": None, "results": [], "invocations": [None]}]}, Capability.supported),
    }
    for name, (data, status) in shapes.items():
        path = tmp_path / f"{name}.sarif"
        path.write_text(json.dumps(data))
        outcome = parse_sarif(path, "t")
        assert outcome.alerts == [] and outcome.status == status, name
        assert outcome.errors if status != Capability.supported else not outcome.errors, name
