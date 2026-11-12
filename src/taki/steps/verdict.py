"""판정과 정책 계산. 값을 고치지 않는 순수 함수이고, LLM의 주장은 근거 확인과 재검토를 거쳐야 판정이 된다."""

from __future__ import annotations

from taki.schemas.models import (
    Case,
    CaseSource,
    Claim,
    EvidenceCheck,
    EvidencePath,
    Finding,
    Outcome,
    Review,
    ReviewResult,
    Role,
    Verdict,
    VerdictState,
    make_claim_key,
    make_finding_id,
)

BLOCK_REVIEWS = 3
OUTCOME_ORDER = {None: 0, Outcome.pass_: 1, Outcome.warn: 2, Outcome.block: 3}
NO_RULE_SOURCES = (CaseSource.question, CaseSource.recheck)
SOURCE_ORDER = {CaseSource.rule: 0, CaseSource.alert: 1, CaseSource.question: 2, CaseSource.recheck: 2}


def root_file(evidence: EvidencePath) -> str | None:
    roots = [h for h in evidence.hops if h.role == Role.root_control]
    hops = roots or evidence.hops
    return hops[0].file if hops else None


def _from_problem_claim(reviews: list[Review]) -> tuple[VerdictState, str]:
    refuted = [r for r in reviews if r.result == ReviewResult.refuted]
    if refuted:
        proven = [
            r
            for r in refuted
            if r.evidence and r.evidence.claim == Claim.implemented and r.evidence_check and r.evidence_check.passed
        ]
        if proven:
            return VerdictState.implemented, f"재검토가 근거를 들어 기각: {proven[0].reason}"
        return VerdictState.unverified, f"재검토가 기각했지만 근거를 확인하지 못함: {refuted[0].reason}"
    if not reviews or any(r.result != ReviewResult.kept for r in reviews):
        return VerdictState.unverified, "재검토에서 확인하지 못함"
    return VerdictState.missing_suspected, "근거 확인을 통과하고 재검토에서 유지됨"


def decide(
    case_id: str,
    evidence: EvidencePath | None,
    check: EvidenceCheck | None,
    reviews: list[Review],
    code_hash: str,
    error: str | None = None,
) -> Verdict:
    if check and check.fixed_hops and evidence:
        evidence = evidence.model_copy(update={"hops": check.fixed_hops})

    if error or evidence is None:
        state, reason = VerdictState.unverified, error or "주장이 없음"
    elif not check or not check.passed:
        failures = [f.value for f in check.failures] if check else []
        state, reason = VerdictState.unverified, f"근거 확인 실패: {failures}"
    elif evidence.claim == Claim.implemented:
        state, reason = VerdictState.implemented, "구현 근거 확인"
    elif evidence.claim == Claim.not_applicable:
        state, reason = VerdictState.not_applicable, evidence.statement
    else:
        state, reason = _from_problem_claim(reviews)

    claim_key = make_claim_key(root_file(evidence), evidence.root_symbol, evidence.category) if evidence else ""
    return Verdict(
        case_id=case_id,
        claim_key=claim_key,
        state=state,
        reason=reason,
        evidence=evidence,
        check=check,
        reviews=reviews,
        code_hash=code_hash,
    )


def policy_outcome(verdict: Verdict, *, tool_confirmed: bool, rule_approved: bool) -> Outcome | None:
    if verdict.state == VerdictState.implemented:
        return Outcome.pass_
    if verdict.state == VerdictState.not_applicable:
        return None
    kept = sum(r.result == ReviewResult.kept for r in verdict.reviews)
    # AI 근거만으로는 막지 않는다. 도구나 승인된 탐지 규칙이 같은 위반을 확인해야 한다.
    if verdict.state == VerdictState.missing_suspected and (tool_confirmed or rule_approved) and kept >= BLOCK_REVIEWS:
        return Outcome.block
    return Outcome.warn


def group_findings(verdicts: list[Verdict], cases: list[Case], tool_confirmed_ids: set[str]) -> list[Finding]:
    """같은 원인의 주장을 이슈 하나로 묶는다. 규칙 항목을 먼저 처리해 질문·경고 주장이 규칙 이슈에 합쳐지게 한다."""
    case_by_id = {c.case_id: c for c in cases}
    findings: dict[str, Finding] = {}
    members: dict[str, list[Verdict]] = {}
    by_root: dict[tuple, str] = {}
    ordered = sorted(verdicts, key=lambda v: SOURCE_ORDER[case_by_id[v.case_id].source])
    for verdict in ordered:
        evidence = verdict.evidence
        if evidence is None or verdict.state not in (VerdictState.missing_suspected, VerdictState.unverified):
            continue
        case = case_by_id[verdict.case_id]
        file = root_file(evidence)
        root = (file, evidence.root_symbol, evidence.category)
        if case.source == CaseSource.rule:
            finding_id = make_finding_id(file, evidence.root_symbol, case.subject_id)
        else:
            finding_id = by_root.get(root) or make_finding_id(
                file, evidence.root_symbol, f"{case.source.value}:{evidence.category}"
            )
        by_root.setdefault(root, finding_id)
        finding = findings.setdefault(
            finding_id,
            Finding(
                finding_id=finding_id,
                state=verdict.state,
                root_file=file,
                root_symbol=evidence.root_symbol,
                broken_rule=None if case.source in NO_RULE_SOURCES else case.subject_id,
                cwe=evidence.cwe,
                category=evidence.category,
                statement=evidence.statement,
            ),
        )
        finding.evidence.append(evidence)
        if case.case_id not in finding.case_ids:
            finding.case_ids.append(case.case_id)
        if case.flow_id and case.flow_id not in finding.flows:
            finding.flows.append(case.flow_id)
        if verdict.state == VerdictState.missing_suspected:
            finding.state = verdict.state
            if case.source == CaseSource.alert:
                finding.tool_confirmed = True
        members.setdefault(finding_id, []).append(verdict)

    for finding_id, finding in findings.items():
        finding.tool_confirmed = finding.tool_confirmed or finding_id in tool_confirmed_ids
        outcomes = [
            policy_outcome(v, tool_confirmed=finding.tool_confirmed, rule_approved=False) for v in members[finding_id]
        ]
        finding.outcome = max(outcomes, key=OUTCOME_ORDER.__getitem__)
    # 조사 자체가 실패한 항목도 이슈로 남긴다. 그래야 화면과 API에서 "0건"으로 보이지 않는다.
    for verdict in verdicts:
        if verdict.evidence is None and verdict.state == VerdictState.unverified:
            case = case_by_id[verdict.case_id]
            finding_id = make_finding_id(None, case.case_id, case.subject_id)
            findings.setdefault(
                finding_id,
                Finding(
                    finding_id=finding_id,
                    state=VerdictState.unverified,
                    statement=f"조사하지 못함: {verdict.reason}",
                    broken_rule=None if case.source in NO_RULE_SOURCES else case.subject_id,
                    flows=[case.flow_id] if case.flow_id else [],
                    outcome=Outcome.warn,
                    case_ids=[case.case_id],
                ),
            )
    return list(findings.values())
