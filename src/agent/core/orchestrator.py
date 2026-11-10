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
from agent.adapters.scanner.semgrep import coverage_gaps, run_semgrep
from agent.config import AgentConfig
from agent.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from agent.llm.roles import investigate, propose_fix, review
from agent.schemas.models import (
    Capability,
    Case,
    CaseSource,
    CheckFailure,
    Claim,
    EvidenceCheck,
    EvidencePath,
    Finding,
    Flow,
    LedgerCell,
    LedgerState,
    Outcome,
    Review,
    ReviewResult,
    RuleStatus,
    RunMode,
    SecurityRule,
    Slice,
    Snapshot,
    Verdict,
    VerdictState,
)
from agent.steps.cases import build_cases, pass_through_alerts, update_ledger
from agent.steps.evidence import check_evidence
from agent.steps.lenses import load_lenses
from agent.steps.recheck import PROBLEM_STATES, RecheckItem, compare_runs
from agent.steps.report import write_report
from agent.steps.scope import scan_scope
from agent.steps.slices import build_slices, fallback_slices, load_slices, locate_handlers, render_slice
from agent.steps.verdict import decide, group_findings
from agent.tools.readonly import ReadOnlyTools

LLM_ERRORS = (LlmCallError, LlmFormatError, BudgetExceeded, SecretLeft)
QUOTE_FAILURES = {CheckFailure.quote_not_found, CheckFailure.quote_ambiguous}


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


def _flows_for(case: Case, slice_: Slice, claim: EvidencePath) -> list[Flow]:
    if case.flow_id:
        return [f for f in slice_.flows if f.flow_id == case.flow_id]
    return [f for f in slice_.flows if f.handler_symbol == claim.root_symbol] or slice_.flows


def _quote_feedback(claims: list[EvidencePath], checks: list[EvidenceCheck]) -> str:
    wrong = [
        f"{hop.file}:{hop.start} {sorted(f.value for f in QUOTE_FAILURES & set(check.failures))}"
        for claim, check in zip(claims, checks)
        if QUOTE_FAILURES & set(check.failures)
        for hop in claim.hops
    ]
    return "이전 응답의 인용을 코드에서 찾지 못했다. 코드 문장을 그대로 복사하고 줄 번호를 맞춰 다시 내라:\n" + "\n".join(wrong)


def _review_claim(claim, check, slice_text, snapshot, flows, gateway, case, sent, tools) -> Review:
    fixed = claim.model_copy(update={"hops": check.fixed_hops})
    try:
        result = review(fixed, slice_text, gateway=gateway, case_id=case.case_id, sent_files=sent, tools=tools)
    except LLM_ERRORS as e:
        return Review(result=ReviewResult.not_proven, reason=f"재검토 호출 실패: {e}")
    if result.result == ReviewResult.refuted and result.evidence:
        result.evidence_check = check_evidence(result.evidence, snapshot, flows)
    return result


def _case_trace_inputs(inputs: dict) -> dict:
    """조사 항목 추적에는 ID와 질문만 남긴다. 코드 원문은 넣지 않는다."""
    case = inputs["case"]
    return {"case_id": case.case_id, "source": case.source.value, "subject": case.subject_id, "question": case.question,
            "slice": inputs["slice_"].name, "flow": case.flow_id}


def _verdict_trace_outputs(verdicts) -> dict:
    return {"verdicts": [{"state": v.state.value, "reason": v.reason, "claim_key": v.claim_key} for v in verdicts]}


@traceable(name="조사 항목", run_type="chain", process_inputs=_case_trace_inputs, process_outputs=_verdict_trace_outputs)
def _run_case(case: Case, slice_: Slice, rule: SecurityRule | None, snapshot, gateway, ledger, tools, lenses) -> list[Verdict]:
    slice_text = render_slice(slice_, snapshot)
    sent = [f.path for f in slice_.files]
    requirement = f"{rule.doc_ref}: {rule.requirement_quote}" if rule and rule.requirement_quote else None
    ask = {"gateway": gateway, "requirement": requirement, "sent_files": sent, "tools": tools}
    try:
        result = investigate(case, slice_text, **ask)
        checks = [check_evidence(c, snapshot, _flows_for(case, slice_, c)) for c in result.claims]
        if any(QUOTE_FAILURES & set(c.failures) for c in checks):
            result = investigate(case, slice_text, feedback=_quote_feedback(result.claims, checks), **ask)
    except LLM_ERRORS as e:
        update_ledger(ledger, case, None, error=str(e), lenses=lenses)
        return [decide(case.case_id, None, None, [], slice_.code_hash, error=str(e))]

    if case.source == CaseSource.question:
        # 답만 있고 주장이 없으면 판정을 만들지 않는다. "이상을 찾지 못함"은 구현 확인이 아니다.
        update_ledger(ledger, case, result, lenses=lenses)
    else:
        update_ledger(ledger, case, result, error=None if result.claims else "주장이 없음")
        if not result.claims:
            return [decide(case.case_id, None, None, [], slice_.code_hash)]

    verdicts = []
    for claim in result.claims:
        flows = _flows_for(case, slice_, claim)
        check = check_evidence(claim, snapshot, flows)
        reviews = []
        if check.passed and claim.claim in (Claim.absent, Claim.defect):
            reviews.append(_review_claim(claim, check, slice_text, snapshot, flows, gateway, case, sent, tools))
        verdicts.append(decide(case.case_id, claim, check, reviews, slice_.code_hash))
    return verdicts


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


def _run_scanners(snapshot: Snapshot, config: AgentConfig, out: Path, result: RunResult) -> list:
    if not config.semgrep.enabled:
        result.ledger.append(LedgerCell(subject="semgrep", target="*", state=LedgerState.deferred,
                                        reason="스캐너가 꺼져 있어 실행하지 않음"))
        return []
    outcome = run_semgrep(snapshot, config.semgrep, out)
    if outcome.status != Capability.supported:
        result.ledger.append(LedgerCell(subject="semgrep", target="*", state=LedgerState.not_seen,
                                        reason="; ".join(outcome.errors) or outcome.status.value))
    return outcome.alerts


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
    with tracing_context(enabled=bool(config.langsmith_project), project_name=config.langsmith_project,
                         tags=["secagent", mode.value]):
        return _scan(target, design=design, out=out, config=config, mode=mode, slices_file=slices_file, rules=rules,
                     previous=previous, alerts=alerts)


@traceable(name="secagent 검사", run_type="chain", process_inputs=_scan_trace_inputs, process_outputs=_scan_trace_outputs)
def _scan(target, *, design, out, config: AgentConfig, mode: RunMode, slices_file, rules, previous, alerts) -> RunResult:
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
    if slices_file is not None:
        slices = load_slices(Path(slices_file), snapshot)
        locate_handlers(slices, index)
    else:
        slices = _auto_slices(snapshot, design, result, index, mappers, spring)
        if slices is None:
            return _finish(result, out, 3, "Spring 프로젝트인데 컨트롤러를 찾지 못했습니다.")
    result.slices = slices
    alerts = [*alerts, *_run_scanners(snapshot, config, out, result)]
    lenses = load_lenses()
    result.cases = cases = build_cases(slices, list(rules), config.budget, lenses=lenses, alerts=alerts)
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
    for case in cases:
        verdicts = _run_case(case, slice_by_id[case.slice_id], rule_by_id.get(case.subject_id), snapshot, gateway,
                             result.ledger, tools, lenses)
        for v in verdicts:
            v.manifest_ids = list(gateway.manifest_ids_by_case.get(case.case_id, []))
        result.verdicts += verdicts

    result.findings = group_findings(result.verdicts, cases, set())
    _add_fixes(result.findings, cases, slices, snapshot, gateway)
    investigated = {v.case_id for v in result.verdicts if v.evidence is not None}
    failed_alerts = {c.case_id for c in cases if c.source == CaseSource.alert and c.case_id not in investigated}
    result.findings += pass_through_alerts(alerts, slices, failed_alerts)
    result.ledger += coverage_gaps(config.semgrep.rule_files() if config.semgrep.enabled else [])

    _finish(result, out)
    if previous is not None:
        result.recheck = compare_runs(Path(previous), out)
        _finish(result, out)
    return result
