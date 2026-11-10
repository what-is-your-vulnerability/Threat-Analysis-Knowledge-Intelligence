"""이슈마다 취약 경로(호출 순서)를 뽑는다. 그림과 report.json에 쓰며 코드 원문은 넣지 않는다."""

from __future__ import annotations

from agent.schemas.models import Certainty, Hop, Role, VerdictState

PATH_STATES = {VerdictState.missing_suspected, VerdictState.unverified}


def _step(hop: Hop, source: str, symbol: str | None) -> dict:
    return {"file": hop.file, "start": hop.start, "end": hop.end, "symbol": symbol, "role": hop.role.value,
            "source": source}


def _covered(hop: Hop, steps: list[dict]) -> bool:
    return any(s["file"] == hop.file and s["start"] <= hop.end and hop.start <= s["end"] for s in steps)


def finding_paths(result) -> list[dict]:
    flows = {f.flow_id: f for s in result.slices for f in s.flows}
    paths = []
    for finding in result.findings:
        if not (finding.tool_confirmed or (finding.state in PATH_STATES and finding.evidence)):
            continue
        # 흐름이 여럿이어도 첫 흐름만 쓴다. 다른 API의 경로를 이어 붙이면 없는 호출을 그리게 된다.
        flow = next((flows[i] for i in finding.flows if i in flows and flows[i].hops), None)
        steps = [_step(h, "flow", flow.handler_symbol if h.role == Role.entrypoint else None)
                 for h in (flow.hops if flow else [])]
        for evidence in finding.evidence:
            for hop in evidence.hops:
                if not _covered(hop, steps):
                    source = "tool" if hop.certainty == Certainty.tool_confirmed else "evidence"
                    steps.append(_step(hop, source, evidence.root_symbol if hop.role == Role.root_control else None))
        if steps:
            paths.append({"finding_id": finding.finding_id, "cwe": finding.cwe, "state": finding.state.value,
                          "statement": finding.statement, "steps": steps})
    return paths
