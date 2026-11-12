"""문제 주장을 SARIF로 바꾼다. 다른 도구 결과와 같은 채점기로 잴 수 있게 한다."""

from __future__ import annotations

from taki.schemas.models import Claim, EvidencePath, Hop, Role

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _location(hop: Hop) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": hop.file},
            "region": {"startLine": hop.start, "endLine": hop.end},
        }
    }


def _result(path: EvidencePath) -> dict:
    roots = [h for h in path.hops if h.role == Role.root_control]
    first = roots[0] if roots else (path.hops[0] if path.hops else None)
    result = {
        "ruleId": path.cwe or "agent-finding",
        "level": "warning",
        "message": {"text": path.statement},
        "properties": {"cwe": path.cwe, "category": path.category, "claim": path.claim.value},
        "locations": [_location(first)] if first else [],
    }
    if path.hops:
        result["codeFlows"] = [{"threadFlows": [{"locations": [{"location": _location(h)} for h in path.hops]}]}]
    return result


def to_sarif(paths: list[EvidencePath], *, tool_name: str) -> dict:
    results = [_result(p) for p in paths if p.claim in (Claim.absent, Claim.defect)]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name, "rules": []}}, "results": results}],
    }
