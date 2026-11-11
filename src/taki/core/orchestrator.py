"""검사 흐름 그래프. SAST를 먼저 병렬로 돌리고, 그 결과와 기능 묶음으로 조사 항목을 만들어 하나씩 조사한다.

prepare → scanner(도구마다 병렬) → structure → plan_cases → run_one_case(반복) → findings → report
판정·차단은 단계 함수가 프로그램으로 정한다. LLM은 조사 항목 그래프 안에서만 부른다.
"""

from __future__ import annotations

import json
import operator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send
from langsmith import tracing_context

from taki.adapters.lang.java_index import build_index
from taki.adapters.lang.mybatis import parse_mappers
from taki.adapters.lang.spring import extract_spring
from taki.adapters.repo.local import check_allowed, open_target
from taki.adapters.scanner.docker import keep_snapshot_alerts, plan_scanners, run_scanner
from taki.adapters.scanner.sarif import ScanOutcome, coverage_gaps
from taki.config import AgentConfig
from taki.core.case_graph import LLM_ERRORS, ScanRuntime, run_case
from taki.core.tracing import trace_client
from taki.llm.gateway import LlmGateway
from taki.llm.roles import propose_fix
from taki.schemas.models import (
    Capability,
    Case,
    CaseSource,
    Finding,
    LedgerCell,
    LedgerState,
    Outcome,
    RuleStatus,
    RunMode,
    Slice,
    Snapshot,
    Verdict,
    VerdictState,
)
from taki.steps.cases import alerts_by_slice, build_cases, pass_through_alerts
from taki.steps.lenses import load_lenses
from taki.steps.recheck import PROBLEM_STATES, RecheckItem, compare_runs
from taki.steps.report import write_report
from taki.steps.scope import scan_scope
from taki.steps.slices import build_slices, fallback_slices, load_slices, locate_handlers, render_slice
from taki.steps.verdict import group_findings
from taki.tools.readonly import ReadOnlyTools


@dataclass
class RunResult:
    exit_code: int = 0
    findings: list[Finding] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    ledger: list[LedgerCell] = field(default_factory=list)
    out: Path | None = None
    mode: RunMode = RunMode.full
    snapshot: Snapshot | None = None
    slices: list[Slice] = field(default_factory=list)
    cases: list[Case] = field(default_factory=list)
    recheck: list[RecheckItem] = field(default_factory=list)
    error: str | None = None


def _add_fixes(findings, cases, slices, snapshot, gateway) -> None:
    case_by_id = {c.case_id: c for c in cases}
    slice_by_id = {s.slice_id: s for s in slices}
    for finding in findings:
        if finding.state != VerdictState.missing_suspected:
            continue
        case = case_by_id[finding.case_ids[0]]
        slice_ = slice_by_id[case.slice_id]
        try:
            finding.fix = propose_fix(finding.evidence[0], render_slice(slice_, snapshot), gateway=gateway,
                                      case_id=case.case_id, sent_files=[f.path for f in slice_.files])
        except LLM_ERRORS:
            finding.fix = None  # 제안이 없어도 판정은 그대로다. 리포트에는 수정 방법이 비어 있게 나온다.


def _auto_slices(snapshot: Snapshot, design, index, mappers, spring) -> tuple[list[Slice] | None, list[LedgerCell]]:
    cells = [LedgerCell(subject="매퍼 읽기", target="*", state=LedgerState.not_seen, reason=e) for e in mappers.errors]
    state = spring.capabilities["entrypoints"]
    if state == Capability.failed:
        return None, cells
    if state == Capability.unsupported:
        cells.append(LedgerCell(subject="프레임워크", target="*", state=LedgerState.not_seen,
                                reason="알아보는 프레임워크가 없어 진입점을 뽑지 못하고 폴더 단위로 나눔"))
        return fallback_slices(snapshot), cells
    return build_slices(snapshot, spring.entrypoints, index, mappers, design_docs=design), cells


CODE_LANGUAGES = {"typescript", "javascript", "python", "c", "proc"}


def _code_outside_slices(snapshot: Snapshot, slices: list[Slice]) -> list[LedgerCell]:
    """어느 묶음에도 들어가지 않은 Java 밖의 코드 파일을 못 본 범위로 알린다."""
    in_slices = {f.path for s in slices for f in s.files}
    missed = [f.path for f in snapshot.files if f.language in CODE_LANGUAGES and f.path not in in_slices]
    if not missed:
        return []
    shown = ", ".join(missed[:10]) + (" 외" if len(missed) > 10 else "")
    return [LedgerCell(subject="묶음 밖 코드", target="*", state=LedgerState.not_seen,
                       reason=f"어느 기능 묶음에도 들어가지 않아 보지 못한 코드 파일 {len(missed)}개: {shown}")]


def _recheck_cases(previous: Path, slices: list[Slice], budget) -> list[Case]:
    """고정 질문·스캐너 경고로 찾은 이전 문제마다 지금도 맞는지 다시 묻는다. 같은 항목 ID를 써야 재검사에서 비교된다."""
    report = json.loads((previous / "report.json").read_text(encoding="utf-8"))
    previous_cases = {c["case_id"]: c for c in report.get("cases", [])}
    slice_ids = {s.slice_id for s in slices}
    cases: dict[str, Case] = {}
    for verdict in report["verdicts"]:
        case = previous_cases.get(verdict["case_id"])
        evidence = verdict.get("evidence")
        if (not case or case["source"] not in ("question", "alert", "recheck") or not evidence
                or verdict["state"] not in PROBLEM_STATES or case["slice_id"] not in slice_ids):
            continue
        claim = (f"이전 검사의 주장: {evidence['statement']} (위치 {evidence.get('root_symbol')}, {evidence.get('cwe')}). "
                 "지금 코드에서도 맞는지 확인하라. 고쳐졌으면 고친 코드를 implemented 근거로, 남아 있으면 문제 주장으로 낸다.")
        if case["case_id"] in cases:
            cases[case["case_id"]].question += "\n" + claim
        else:
            cases[case["case_id"]] = Case(case_id=case["case_id"], source=CaseSource.recheck, subject_id=case["subject_id"],
                                          question=claim, slice_id=case["slice_id"], budget=budget)
    return list(cases.values())


def _exit_code(result: RunResult) -> int:
    if any(f.outcome == Outcome.block for f in result.findings):
        return 2
    has_problem = any(v.state in (VerdictState.missing_suspected, VerdictState.unverified) for v in result.verdicts)
    warned = any(f.outcome == Outcome.warn for f in result.findings)
    not_seen = any(c.state == LedgerState.not_seen for c in result.ledger)
    not_fixed = any(i.change != "resolved" for i in result.recheck)
    nothing_checked = not result.verdicts and not any(
        c.state == LedgerState.checked and not c.subject.startswith("scanner:") for c in result.ledger)
    return 1 if has_problem or warned or not_seen or not_fixed or nothing_checked else 0


def _finish(result: RunResult, out: Path, code: int | None = None, error: str | None = None) -> RunResult:
    result.error = error
    result.exit_code = _exit_code(result) if code is None else code
    write_report(result, out)
    return result


# 항목 하나가 run_one_case 한 단계다. 기본 재귀 한도(25)로는 항목 20여 개에서 멈춘다.
RECURSION_LIMIT = 10_000


class ScanState(TypedDict, total=False):
    # 입력. AgentConfig는 config 대신 settings로 둔다(LangChain 실행 설정 이름과 겹치지 않게).
    target: Any
    design: list
    out: Path
    settings: AgentConfig
    mode: RunMode
    slices_file: Any
    rules: list
    previous: Any
    # 단계 결과
    snapshot: Any
    scanners: list
    runtime: Any
    slices: list
    cases: list
    capped_cases: list  # 상한을 넘어 조사하지 않은 경고 항목 ID
    next_case: int
    alerts: list  # 분석 범위 안 경고(structure가 거른 결과)
    findings: list
    exit_code: int | None
    error: str | None
    result: Any
    # 여러 노드가 쌓는 값
    raw_alerts: Annotated[list, operator.add]
    ledger: Annotated[list, operator.add]
    verdicts: Annotated[list, operator.add]
    covered_cwes: Annotated[list, operator.add]


def _prepare(state: ScanState) -> dict:
    out = Path(state["out"])
    out.mkdir(parents=True, exist_ok=True)
    for path in state["design"]:
        check_allowed(Path(path).resolve())
    snapshot = scan_scope(open_target(Path(state["target"]), out / "_target"), exclude=(out.resolve(),))
    if snapshot.status == Capability.failed:
        return {"out": out, "snapshot": snapshot, "exit_code": 3, "error": "분석할 파일이 없습니다."}
    scanners, cells = plan_scanners(state["settings"].scanners, snapshot)
    return {"out": out, "snapshot": snapshot, "scanners": scanners, "ledger": cells}


def _after_prepare(state: ScanState):
    if state["exit_code"] is not None:
        return "report"
    sends = [Send("scanner", {"spec": spec, "snapshot": state["snapshot"], "out": state["out"]})
             for spec in state["scanners"]]
    return sends or "structure"


def _scanner(task: dict) -> dict:
    spec = task["spec"]
    try:
        outcome = run_scanner(spec, task["snapshot"], task["out"])
    except Exception as e:  # noqa: BLE001 - 도구 하나의 처리 오류가 다른 도구 결과와 검사 전체를 버리게 하지 않는다
        outcome = ScanOutcome(Capability.failed, errors=[f"스캐너 처리 오류: {type(e).__name__}: {e}"])
    if outcome.status == Capability.supported:
        # 재검사는 같은 도구가 정상 실행된 기록이 있어야 도구 결과로만 실린 이슈를 해결로 친다.
        cell = LedgerCell(subject=f"scanner:{spec.name}", target="*", state=LedgerState.checked, reason="실행함")
    else:
        cell = LedgerCell(subject=f"scanner:{spec.name}", target="*", state=LedgerState.not_seen,
                          reason="; ".join(outcome.errors) or outcome.status.value)
    return {"raw_alerts": outcome.alerts, "ledger": [cell], "covered_cwes": sorted(outcome.covered_cwes)}


def _structure(state: ScanState) -> dict:
    snapshot, settings, design = state["snapshot"], state["settings"], state["design"]
    gateway = LlmGateway(settings, state["out"])
    index = build_index(snapshot)
    mappers = parse_mappers(snapshot)
    spring = extract_spring(snapshot, index)
    snapshot.capabilities |= {f"spring.{k}": v for k, v in spring.capabilities.items()}
    reader = ReadOnlyTools(snapshot, index, mappers, spring.entrypoints, design)
    runtime = ScanRuntime(gateway=gateway, reader=reader, index=index, mappers=mappers, spring=spring,
                          lenses=load_lenses())
    alerts, dropped = keep_snapshot_alerts(state["raw_alerts"], snapshot)
    if state["slices_file"] is not None:
        slices = load_slices(Path(state["slices_file"]), snapshot)
        locate_handlers(slices, index)
        return {"runtime": runtime, "alerts": alerts, "ledger": dropped, "slices": slices}
    slices, cells = _auto_slices(snapshot, design, index, mappers, spring)
    update = {"runtime": runtime, "alerts": alerts, "ledger": [*dropped, *cells], "slices": slices or []}
    if slices is None:
        return {**update, "exit_code": 3, "error": "Spring 프로젝트인데 컨트롤러를 찾지 못했습니다."}
    return update


def _plan_cases(state: ScanState) -> dict:
    settings, slices, rules, design = state["settings"], state["slices"], list(state["rules"]), state["design"]
    cases = build_cases(slices, rules, settings.budget, lenses=state["runtime"].lenses, alerts=state["alerts"])
    capped = [c.case_id for c in cases if c.source == CaseSource.alert][settings.max_alert_cases:]
    cases = [c for c in cases if c.case_id not in capped]
    if state["previous"] is not None:
        cases += _recheck_cases(Path(state["previous"]), slices, settings.budget)
    cells = _code_outside_slices(state["snapshot"], slices)
    if capped:
        cells.append(LedgerCell(subject="경고 항목 상한", target="*", state=LedgerState.not_seen,
                                reason=f"상한 {settings.max_alert_cases}개를 넘은 경고 항목 {len(capped)}개는 "
                                       "AI 확인 없이 도구 결과로만 실음"))
    if design and not any(r.status == RuleStatus.approved for r in rules):
        cells.append(LedgerCell(
            subject="설계문서", target="*", state=LedgerState.not_seen,
            reason="승인된 보안 규칙이 없어 설계 요구를 직접 대조하지 못함. taki rules derive로 후보를 만들어 승인한다.",
        ))
    cells += [LedgerCell(subject=rule.rule_id, target="*", state=LedgerState.not_seen, reason="승인되지 않았거나 맞는 API가 없음")
              for rule in rules if not any(c.subject_id == rule.rule_id for c in cases)]
    return {"cases": cases, "capped_cases": capped, "ledger": cells, "next_case": 0}


def _run_one_case(state: ScanState) -> dict:
    case = state["cases"][state["next_case"]]
    slice_ = next(s for s in state["slices"] if s.slice_id == case.slice_id)
    rule = next((r for r in state["rules"] if r.rule_id == case.subject_id), None)
    shown = alerts_by_slice(state["alerts"], state["slices"]).get(case.slice_id, ())
    verdicts, cells = run_case(case, slice_, rule, state["snapshot"], state["runtime"], shown)
    return {"verdicts": verdicts, "ledger": cells, "next_case": state["next_case"] + 1}


def _more_cases(state: ScanState) -> str:
    return "run_one_case" if state["next_case"] < len(state["cases"]) else "findings"


def _findings(state: ScanState) -> dict:
    cases, slices, verdicts = state["cases"], state["slices"], state["verdicts"]
    findings = group_findings(verdicts, cases, set())
    _add_fixes(findings, cases, slices, state["snapshot"], state["runtime"].gateway)
    investigated = {v.case_id for v in verdicts if v.evidence is not None}
    failed_alerts = {c.case_id for c in cases if c.source == CaseSource.alert and c.case_id not in investigated}
    failed_alerts |= set(state["capped_cases"])  # 상한으로 조사하지 않은 경고도 실패한 경고처럼 도구 결과로 싣는다
    findings += pass_through_alerts(state["alerts"], slices, failed_alerts)
    return {"findings": findings, "ledger": coverage_gaps(set(state["covered_cwes"]))}


def _report(state: ScanState) -> dict:
    out = state["out"]
    result = RunResult(out=out, mode=state["mode"], snapshot=state["snapshot"], slices=state["slices"],
                       cases=state["cases"], findings=state["findings"], verdicts=state["verdicts"],
                       ledger=state["ledger"])
    _finish(result, out, state["exit_code"], state["error"])
    if state["previous"] is not None and state["exit_code"] is None:
        result.recheck = compare_runs(Path(state["previous"]), out)
        _finish(result, out)
    return {"result": result}


def _build():
    graph = StateGraph(ScanState)
    for name, node in [("prepare", _prepare), ("scanner", _scanner), ("structure", _structure),
                       ("plan_cases", _plan_cases), ("run_one_case", _run_one_case), ("findings", _findings),
                       ("report", _report)]:
        graph.add_node(name, node)
    graph.add_edge(START, "prepare")
    graph.add_conditional_edges("prepare", _after_prepare, ["scanner", "structure", "report"])
    graph.add_edge("scanner", "structure")
    graph.add_conditional_edges("structure", lambda s: "report" if s["exit_code"] is not None else "plan_cases",
                                ["report", "plan_cases"])
    graph.add_conditional_edges("plan_cases", _more_cases, ["run_one_case", "findings"])
    graph.add_conditional_edges("run_one_case", _more_cases, ["run_one_case", "findings"])
    graph.add_edge("findings", "report")
    graph.add_edge("report", END)
    return graph.compile()


SCAN_GRAPH = _build()


def run_scan(target, *, design, out, config: AgentConfig, mode: RunMode = RunMode.full, slices_file=None, rules=(),
             previous=None, alerts=()) -> RunResult:
    state: ScanState = {
        "target": target, "design": list(design), "out": Path(out), "settings": config, "mode": mode,
        "slices_file": slices_file, "rules": list(rules), "previous": previous, "snapshot": None, "scanners": [],
        "runtime": None, "slices": [], "cases": [], "capped_cases": [], "next_case": 0, "alerts": [], "findings": [], "exit_code": None,
        "error": None, "result": None, "raw_alerts": list(alerts), "ledger": [], "verdicts": [], "covered_cwes": [],
    }
    # 설정으로 켰을 때만 LangSmith로 보낸다. 셸 환경변수만 켜져 있으면 보내지 않는다.
    project = config.langsmith_project
    with tracing_context(enabled=bool(project), project_name=project, tags=["taki", mode.value],
                         client=trace_client() if project else None):
        final = SCAN_GRAPH.invoke(state, {"recursion_limit": RECURSION_LIMIT, "run_name": "taki 검사"})
    return final["result"]
