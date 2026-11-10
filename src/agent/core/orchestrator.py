"""검사 순서와 한도를 맡는다. 단계 함수를 차례로 부르는 순수 Python이다."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agent.adapters.repo.local import check_allowed, open_target
from agent.config import AgentConfig
from agent.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from agent.llm.roles import investigate, propose_fix, review
from agent.schemas.models import (
    Capability,
    Case,
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
    RunMode,
    SecurityRule,
    Slice,
    Snapshot,
    Verdict,
    VerdictState,
    make_finding_id,
)
from agent.steps.cases import build_cases, update_ledger
from agent.steps.evidence import check_evidence
from agent.steps.recheck import RecheckItem, compare_runs
from agent.steps.report import write_report
from agent.steps.scope import scan_scope
from agent.steps.slices import load_slices, render_slice
from agent.steps.verdict import decide, group_findings, root_file

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


def _review_claim(claim, check, slice_text, snapshot, flows, gateway, case, sent) -> Review:
    fixed = claim.model_copy(update={"hops": check.fixed_hops})
    try:
        result = review(fixed, slice_text, gateway=gateway, case_id=case.case_id, sent_files=sent)
    except LLM_ERRORS as e:
        return Review(result=ReviewResult.not_proven, reason=f"재검토 호출 실패: {e}")
    if result.result == ReviewResult.refuted and result.evidence:
        result.evidence_check = check_evidence(result.evidence, snapshot, flows)
    return result


def _run_case(case: Case, slice_: Slice, rule: SecurityRule | None, snapshot, gateway, ledger) -> list[Verdict]:
    slice_text = render_slice(slice_, snapshot)
    sent = [f.path for f in slice_.files]
    requirement = f"{rule.doc_ref}: {rule.requirement_quote}" if rule and rule.requirement_quote else None
    ask = {"gateway": gateway, "requirement": requirement, "sent_files": sent}
    try:
        result = investigate(case, slice_text, **ask)
        checks = [check_evidence(c, snapshot, _flows_for(case, slice_, c)) for c in result.claims]
        if any(QUOTE_FAILURES & set(c.failures) for c in checks):
            result = investigate(case, slice_text, feedback=_quote_feedback(result.claims, checks), **ask)
    except LLM_ERRORS as e:
        update_ledger(ledger, case, None, error=str(e))
        return [decide(case.case_id, None, None, [], slice_.code_hash, error=str(e))]

    update_ledger(ledger, case, result, error=None if result.claims else "주장이 없음")
    if not result.claims:
        return [decide(case.case_id, None, None, [], slice_.code_hash)]

    verdicts = []
    for claim in result.claims:
        flows = _flows_for(case, slice_, claim)
        check = check_evidence(claim, snapshot, flows)
        reviews = []
        if check.passed and claim.claim in (Claim.absent, Claim.defect):
            reviews.append(_review_claim(claim, check, slice_text, snapshot, flows, gateway, case, sent))
        verdicts.append(decide(case.case_id, claim, check, reviews, slice_.code_hash))
    return verdicts


def _add_fixes(findings, verdicts, cases, slices, snapshot, gateway) -> None:
    case_by_id = {c.case_id: c for c in cases}
    slice_by_id = {s.slice_id: s for s in slices}
    slice_by_finding: dict[str, tuple[Case, Slice]] = {}
    for v in verdicts:
        if v.evidence:
            case = case_by_id[v.case_id]
            finding_id = make_finding_id(root_file(v.evidence), v.evidence.root_symbol, case.subject_id)
            slice_by_finding.setdefault(finding_id, (case, slice_by_id[case.slice_id]))
    for finding in findings:
        if finding.state != VerdictState.missing_suspected:
            continue
        case, slice_ = slice_by_finding[finding.finding_id]
        try:
            finding.fix = propose_fix(finding.evidence[0], render_slice(slice_, snapshot), gateway=gateway,
                                      case_id=case.case_id, sent_files=[f.path for f in slice_.files])
        except LLM_ERRORS:
            finding.fix = None  # 제안이 없어도 판정은 그대로다. 리포트에는 수정 방법이 비어 있게 나온다.


def _exit_code(result: RunResult) -> int:
    if any(f.outcome == Outcome.block for f in result.findings):
        return 2
    has_problem = any(v.state in (VerdictState.missing_suspected, VerdictState.unverified) for v in result.verdicts)
    not_seen = any(c.state == LedgerState.not_seen for c in result.ledger)
    not_fixed = any(i.change != "resolved" for i in result.recheck)
    return 1 if has_problem or not_seen or not_fixed or not result.verdicts else 0


def _finish(result: RunResult, out: Path, code: int | None = None, error: str | None = None) -> RunResult:
    result.error = error
    result.exit_code = _exit_code(result) if code is None else code
    write_report(result, out)
    return result


def run_scan(
    target,
    *,
    design,
    out,
    config: AgentConfig,
    mode: RunMode = RunMode.full,
    slices_file=None,
    rules=(),
    previous=None,
) -> RunResult:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for path in design:
        check_allowed(Path(path).resolve())

    result = RunResult(out=out, mode=mode)
    result.snapshot = snapshot = scan_scope(open_target(Path(target), out / "_target"))
    if snapshot.status == Capability.failed:
        return _finish(result, out, 3, "분석할 파일이 없습니다.")
    if slices_file is None:
        return _finish(result, out, 3, "기능 묶음 입력이 없습니다.")

    gateway = LlmGateway(config, out)
    result.slices = slices = load_slices(Path(slices_file), snapshot)
    result.cases = cases = build_cases(slices, list(rules), config.budget)
    slice_by_id = {s.slice_id: s for s in slices}
    rule_by_id = {r.rule_id: r for r in rules}

    for rule in rules:
        if not any(c.subject_id == rule.rule_id for c in cases):
            result.ledger.append(LedgerCell(subject=rule.rule_id, target="*", state=LedgerState.not_seen,
                                            reason="승인되지 않았거나 맞는 API가 없음"))
    for case in cases:
        verdicts = _run_case(case, slice_by_id[case.slice_id], rule_by_id.get(case.subject_id), snapshot, gateway,
                             result.ledger)
        for v in verdicts:
            v.manifest_ids = list(gateway.manifest_ids_by_case.get(case.case_id, []))
        result.verdicts += verdicts

    result.findings = group_findings(result.verdicts, cases, set())
    _add_fixes(result.findings, result.verdicts, cases, slices, snapshot, gateway)

    _finish(result, out)
    if previous is not None:
        result.recheck = compare_runs(Path(previous), out)
        _finish(result, out)
    return result
