"""검사 순서와 한도를 맡는다. 단계 함수를 차례로 부르는 순수 Python이다."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from langsmith import traceable, tracing_context

from agent.adapters.lang.java_index import build_index
from agent.adapters.lang.mybatis import parse_mappers
from agent.adapters.lang.spring import extract_spring
from agent.adapters.repo.local import check_allowed, open_target
from agent.adapters.scanner.docker import keep_snapshot_alerts, plan_scanners, run_scanner
from agent.adapters.scanner.sarif import coverage_gaps
from agent.config import AgentConfig
from agent.core.case_graph import LLM_ERRORS, ScanRuntime, run_case
from agent.core.tracing import trace_client
from agent.llm.gateway import LlmGateway
from agent.llm.roles import propose_fix
from agent.schemas.models import (
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
from agent.steps.cases import alerts_by_slice, build_cases, pass_through_alerts
from agent.steps.lenses import load_lenses
from agent.steps.recheck import PROBLEM_STATES, RecheckItem, compare_runs
from agent.steps.report import write_report
from agent.steps.scope import scan_scope
from agent.steps.slices import build_slices, fallback_slices, load_slices, locate_handlers, render_slice
from agent.steps.verdict import group_findings
from agent.tools.readonly import ReadOnlyTools


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


def _auto_slices(snapshot: Snapshot, design, result: RunResult, index, mappers, spring) -> list[Slice] | None:
    result.ledger += [LedgerCell(subject="매퍼 읽기", target="*", state=LedgerState.not_seen, reason=e) for e in mappers.errors]
    state = spring.capabilities["entrypoints"]
    if state == Capability.failed:
        return None
    if state == Capability.unsupported:
        result.ledger.append(LedgerCell(subject="프레임워크", target="*", state=LedgerState.not_seen,
                                        reason="알아보는 프레임워크가 없어 진입점을 뽑지 못하고 폴더 단위로 나눔"))
        return fallback_slices(snapshot)
    return build_slices(snapshot, spring.entrypoints, index, mappers, design_docs=design)


def _run_scanners(snapshot: Snapshot, config: AgentConfig, out: Path, result: RunResult) -> tuple[list, set[str]]:
    runnable, cells = plan_scanners(config.scanners, snapshot)
    result.ledger += cells
    alerts, covered = [], set()
    for spec in runnable:
        outcome = run_scanner(spec, snapshot, out)
        if outcome.status != Capability.supported:
            result.ledger.append(LedgerCell(subject=f"scanner:{spec.name}", target="*", state=LedgerState.not_seen,
                                            reason="; ".join(outcome.errors) or outcome.status.value))
        alerts += outcome.alerts
        covered |= outcome.covered_cwes
    alerts, dropped = keep_snapshot_alerts(alerts, snapshot)
    result.ledger += dropped
    return alerts, covered


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
    nothing_checked = not result.verdicts and not any(c.state == LedgerState.checked for c in result.ledger)
    return 1 if has_problem or warned or not_seen or not_fixed or nothing_checked else 0


def _finish(result: RunResult, out: Path, code: int | None = None, error: str | None = None) -> RunResult:
    result.error = error
    result.exit_code = _exit_code(result) if code is None else code
    write_report(result, out)
    return result


def _scan_trace_inputs(inputs: dict) -> dict:
    return {"target": str(inputs["target"]), "mode": inputs["mode"].value, "design": [Path(d).name for d in inputs["design"]],
            "rules": len(inputs["rules"])}


def _scan_trace_outputs(result: RunResult) -> dict:
    return {"exit_code": result.exit_code, "error": result.error, "findings": len(result.findings),
            "verdicts": len(result.verdicts), "out": str(result.out)}


def run_scan(target, *, design, out, config: AgentConfig, mode: RunMode = RunMode.full, slices_file=None, rules=(),
             previous=None, alerts=()) -> RunResult:
    # 설정으로 켰을 때만 LangSmith로 보낸다. 셸 환경변수만 켜져 있으면 보내지 않는다.
    project = config.langsmith_project
    with tracing_context(enabled=bool(project), project_name=project, tags=["secagent", mode.value],
                         client=trace_client() if project else None):
        return _scan(target, design=design, out=out, settings=config, mode=mode, slices_file=slices_file, rules=rules,
                     previous=previous, alerts=alerts)


@traceable(name="secagent 검사", run_type="chain", process_inputs=_scan_trace_inputs, process_outputs=_scan_trace_outputs)
def _scan(target, *, design, out, settings: AgentConfig, mode: RunMode, slices_file, rules, previous, alerts) -> RunResult:
    # 인자 이름을 config로 쓰면 langsmith가 LangChain 실행 설정으로 오인한다.
    config = settings
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for path in design:
        check_allowed(Path(path).resolve())

    result = RunResult(out=out, mode=mode)
    result.snapshot = snapshot = scan_scope(open_target(Path(target), out / "_target"), exclude=(out.resolve(),))
    if snapshot.status == Capability.failed:
        return _finish(result, out, 3, "분석할 파일이 없습니다.")

    gateway = LlmGateway(config, out)
    index = build_index(snapshot)
    mappers = parse_mappers(snapshot)
    spring = extract_spring(snapshot, index)
    snapshot.capabilities |= {f"spring.{k}": v for k, v in spring.capabilities.items()}
    tools = ReadOnlyTools(snapshot, index, mappers, spring.entrypoints, design)
    runtime = ScanRuntime(gateway=gateway, reader=tools, index=index, mappers=mappers, spring=spring, lenses=load_lenses())
    if slices_file is not None:
        slices = load_slices(Path(slices_file), snapshot)
        locate_handlers(slices, index)
    else:
        slices = _auto_slices(snapshot, design, result, index, mappers, spring)
        if slices is None:
            return _finish(result, out, 3, "Spring 프로젝트인데 컨트롤러를 찾지 못했습니다.")
    result.slices = slices
    scanner_alerts, covered_cwes = _run_scanners(snapshot, config, out, result)
    alerts = [*alerts, *scanner_alerts]
    result.cases = cases = build_cases(slices, list(rules), config.budget, lenses=runtime.lenses, alerts=alerts)
    if previous is not None:
        cases += _recheck_cases(Path(previous), slices, config.budget)
    result.ledger += _code_outside_slices(snapshot, slices)
    slice_by_id = {s.slice_id: s for s in slices}
    rule_by_id = {r.rule_id: r for r in rules}

    if design and not any(r.status == RuleStatus.approved for r in rules):
        result.ledger.append(LedgerCell(
            subject="설계문서", target="*", state=LedgerState.not_seen,
            reason="승인된 보안 규칙이 없어 설계 요구를 직접 대조하지 못함. secagent rules derive로 후보를 만들어 승인한다.",
        ))
    for rule in rules:
        if not any(c.subject_id == rule.rule_id for c in cases):
            result.ledger.append(LedgerCell(subject=rule.rule_id, target="*", state=LedgerState.not_seen,
                                            reason="승인되지 않았거나 맞는 API가 없음"))
    shown_alerts = alerts_by_slice(alerts, slices)
    for case in cases:
        verdicts, cells = run_case(case, slice_by_id[case.slice_id], rule_by_id.get(case.subject_id), snapshot, runtime,
                                   shown_alerts.get(case.slice_id, ()))
        result.ledger += cells
        result.verdicts += verdicts

    result.findings = group_findings(result.verdicts, cases, set())
    _add_fixes(result.findings, cases, slices, snapshot, gateway)
    investigated = {v.case_id for v in result.verdicts if v.evidence is not None}
    failed_alerts = {c.case_id for c in cases if c.source == CaseSource.alert and c.case_id not in investigated}
    result.findings += pass_through_alerts(alerts, slices, failed_alerts)
    result.ledger += coverage_gaps(covered_cwes)

    _finish(result, out)
    if previous is not None:
        result.recheck = compare_runs(Path(previous), out)
        _finish(result, out)
    return result
