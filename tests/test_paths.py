import json
from pathlib import Path

import pytest
from conftest import make_config

from agent.core.orchestrator import RunResult, run_scan
from agent.llm.roles import InvestigateResult, _ReviewOutput
from agent.llm.tool_loop import submit_tool
from agent.schemas.models import Fact
from agent.steps.cases import load_rules, pass_through_alerts
from agent.steps.paths import finding_paths
from agent.steps.slices import render_slice

FIX = Path(__file__).parent / "fixtures" / "spring-members"
CONTROLLER = "src/main/java/demo/member/MemberController.java"


@pytest.fixture
def scanned(fake, tmp_path):
    """--slices 없이 검사해 Spring 자동 묶음이 호출 경로(hops)를 채우게 한다."""
    fake.responses.extend(json.loads((FIX / "fake_script.json").read_text(encoding="utf-8")))
    out = tmp_path / "run"
    result = run_scan(FIX / "vulnerable", design=[FIX / "design.md"], out=out, config=make_config(fake),
                      rules=load_rules(FIX / "rules.yml"))
    return result, out


def test_missing_admin_check_has_call_path(scanned):
    result, out = scanned
    path = next(p for p in finding_paths(result) if p["cwe"] == "CWE-862")
    steps = path["steps"]
    assert path["state"] == "missing_suspected" and len(steps) >= 2
    assert steps[0]["file"] == CONTROLLER and steps[0]["symbol"] == "MemberController.delete"
    assert steps[1]["file"].endswith("MemberService.java") and steps[0]["source"] == "flow"
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["paths"] == finding_paths(result) and "quote" not in json.dumps(report["paths"])


def test_middle_steps_have_method_names(scanned):
    result, _ = scanned
    steps = next(p for p in finding_paths(result) if p["cwe"] == "CWE-862")["steps"]
    by_file = {Path(s["file"]).name: s["symbol"] for s in steps}
    assert by_file["MemberService.java"] == "MemberService.delete"
    assert by_file["MemberMapper.java"] == "MemberMapper.deleteById"
    assert by_file["MemberMapper.xml"] is None


def test_method_names_stay_out_of_llm_input(scanned):
    result, _ = scanned
    slice_ = next(s for s in result.slices if any(f.symbols for f in s.flows))
    bare = slice_.model_copy(update={"flows": [f.model_copy(update={"symbols": {}}) for f in slice_.flows]})
    assert render_slice(slice_, result.snapshot) == render_slice(bare, result.snapshot)
    assert all("symbols" not in json.dumps(submit_tool(s)) for s in (InvestigateResult, _ReviewOutput))


def _codeql_alert(**detail):
    return Fact(kind="alert", file="A.java", line=9, tool="codeql",
                detail={"cwe": "CWE-89", "rule": "java/sql-injection", "message": "m", "snippet": "q(x)", **detail})


def test_tool_finding_keeps_alert_flow_in_order():
    finding = pass_through_alerts([_codeql_alert(flow=["C.java:2", "B.java:5", "A.java:9"])], [])[0]
    steps = finding_paths(RunResult(findings=[finding]))[0]["steps"]
    assert [(s["file"], s["start"]) for s in steps] == [("C.java", 2), ("B.java", 5), ("A.java", 9)]
    assert {s["source"] for s in steps} == {"tool"} and steps[-1]["role"] == "sink"
    assert finding.finding_id == pass_through_alerts([_codeql_alert()], [])[0].finding_id
