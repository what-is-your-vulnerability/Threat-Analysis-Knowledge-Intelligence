from agent.schemas.models import Claim, EvidencePath, Hop, Role
from agent.steps.sarif import to_sarif


def _path(*hops):
    return EvidencePath(claim=Claim.absent, statement="s", cwe="CWE-862", hops=list(hops))


def test_root_control_is_first_location():
    entry = Hop(file="E.java", start=1, end=1, quote="e", role=Role.entrypoint)
    root = Hop(file="R.java", start=5, end=6, quote="r", role=Role.root_control)
    result = to_sarif([_path(entry, root)], tool_name="agent")["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "R.java" and region["region"]["startLine"] == 5
    assert result["properties"]["cwe"] == "CWE-862"
    flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [x["location"]["physicalLocation"]["artifactLocation"]["uri"] for x in flow] == ["E.java", "R.java"]


def test_no_root_control_uses_first_hop():
    hop = Hop(file="E.java", start=1, end=1, quote="e", role=Role.sink)
    result = to_sarif([_path(hop)], tool_name="agent")["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "E.java"


def test_implemented_claim_is_not_a_result():
    path = EvidencePath(claim=Claim.implemented, statement="s")
    assert to_sarif([path], tool_name="agent")["runs"][0]["results"] == []
