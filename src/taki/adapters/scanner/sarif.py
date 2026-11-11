"""어떤 도구의 SARIF든 공통 경고(Fact)로 바꾼다. 실패는 0건이 아니라 partial이나 failed다."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from taki.schemas.models import Capability, Certainty, Fact, LedgerCell, LedgerState

CWE_RE = re.compile(r"cwe[-_/]?0*(\d+)", re.IGNORECASE)
MAX_FLOW_STEPS = 10
# 탐지 범위 밖 유형. AI가 판정하지 않고, 규칙이 없으면 못 본 범위로 알린다.
OUT_OF_SCOPE_CWES = {"CWE-918": "SSRF", "CWE-22": "경로 조작", "CWE-611": "XXE", "CWE-502": "역직렬화",
                     "CWE-352": "CSRF", "CWE-400": "서비스 거부"}


@dataclass
class ScanOutcome:
    status: Capability
    alerts: list[Fact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    covered_cwes: set[str] = field(default_factory=set)  # 실행된 규칙이 다루는 CWE(결과가 없는 규칙 포함)


def normalize_cwe(text: str) -> str | None:
    """"external/cwe/cwe-089", "CWE-89: ..." 같은 표기를 "CWE-89"로 맞춘다."""
    match = CWE_RE.search(str(text))
    return f"CWE-{int(match.group(1))}" if match else None


# 도구마다 SARIF를 다르게 써서(null, 빠진 키) 객체·목록이 아니면 비어 있는 것으로 읽는다.
def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def _arr(value) -> list:
    return value if isinstance(value, list) else []


def _rule_cwes(rule: dict) -> list[str]:
    props = _obj(rule.get("properties"))
    texts = [*_arr(props.get("tags")), *(props.get("cwe") if isinstance(props.get("cwe"), list) else [props.get("cwe")])]
    found = [normalize_cwe(t) for t in texts if t]
    return list(dict.fromkeys(c for c in found if c))


def _relative(uri: str) -> str:
    return unquote(uri).removeprefix("file://").removeprefix("/src/").removeprefix("./")


def _where(location: dict) -> tuple[str, dict]:
    physical = _obj(_obj(location).get("physicalLocation"))
    return _relative(_obj(physical.get("artifactLocation")).get("uri") or ""), _obj(physical.get("region"))


def _flow(result: dict) -> list[str]:
    for code_flow in _arr(result.get("codeFlows"))[:1]:
        for thread in _arr(_obj(code_flow).get("threadFlows"))[:1]:
            steps = []
            for step in _arr(_obj(thread).get("locations"))[:MAX_FLOW_STEPS]:
                file, region = _where(_obj(step).get("location"))
                steps.append(f"{file}:{region.get('startLine')}")
            return steps
    return []


def parse_sarif(path: Path, tool: str) -> ScanOutcome:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return ScanOutcome(Capability.failed, errors=[f"결과 파일을 읽지 못함: {type(e).__name__}"])
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        return ScanOutcome(Capability.failed, errors=["결과 파일에 실행 결과(runs)가 없음"])
    alerts: list[Fact] = []
    errors: list[str] = []
    covered: set[str] = set()
    for run in map(_obj, runs):
        tool_info = _obj(run.get("tool"))
        driver = _obj(tool_info.get("driver"))
        # CodeQL은 규칙을 driver가 아니라 쿼리 팩(extensions)에 둔다.
        components = [driver, *map(_obj, _arr(tool_info.get("extensions")))]
        rules = {r.get("id"): r for c in components for r in map(_obj, _arr(c.get("rules")))}
        covered |= {cwe for rule in rules.values() for cwe in _rule_cwes(rule)}
        for invocation in map(_obj, _arr(run.get("invocations"))):
            if invocation.get("executionSuccessful") is False:
                errors.append("도구가 실패로 끝남")
            errors += [str(_obj(n.get("message")).get("text") or "")
                       for n in map(_obj, _arr(invocation.get("toolExecutionNotifications"))) if n.get("level") == "error"]
        if not isinstance(run.get("results"), list):
            errors.append("결과 목록이 없음(도구가 결과를 내지 못함)")  # SARIF에서 results가 null이면 실패한 실행이다
        for result in map(_obj, _arr(run.get("results"))):
            rule_id = result.get("ruleId") or _obj(result.get("rule")).get("id")
            cwes = _rule_cwes(_obj(rules.get(rule_id)))
            flow = _flow(result)
            for location in _arr(result.get("locations"))[:1]:
                file, region = _where(location)
                detail = {"rule": rule_id, "cwe": cwes[0] if cwes else None,
                          "message": _obj(result.get("message")).get("text", ""),
                          "snippet": _obj(region.get("snippet")).get("text", "")}
                if flow:
                    detail["flow"] = flow
                alerts.append(Fact(kind="alert", file=file, line=region.get("startLine"), symbol=rule_id, tool=tool,
                                   tool_version=driver.get("semanticVersion") or driver.get("version"),
                                   certainty=Certainty.tool_confirmed, detail=detail))
    return ScanOutcome(Capability.partial if errors else Capability.supported, alerts, errors, covered)


def coverage_gaps(covered: set[str]) -> list[LedgerCell]:
    """규칙이 없는 범위 밖 유형을 알린다. 탐지 범위 밖이라 경고로 치지 않고 deferred로 남긴다."""
    cells = [LedgerCell(subject=f"{name} ({cwe})", target="*", state=LedgerState.deferred, reason="이 유형은 검사 규칙 없음")
             for cwe, name in OUT_OF_SCOPE_CWES.items() if cwe not in covered]
    cells.append(LedgerCell(subject="의존성 CVE", target="*", state=LedgerState.deferred,
                            reason="이 유형은 검사 규칙 없음(라이브러리 점검은 다음 단계)"))
    return cells
