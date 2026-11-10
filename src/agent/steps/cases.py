"""보안 규칙과 기능 묶음에서 조사 항목을 만들고, 무엇을 봤는지 기록한다."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from agent.adapters.scanner.semgrep import OUT_OF_SCOPE_CWES
from agent.schemas.models import (
    Budget,
    Case,
    CaseSource,
    Certainty,
    Claim,
    Disposition,
    EvidencePath,
    Fact,
    Finding,
    Hop,
    LedgerCell,
    LedgerState,
    Outcome,
    Role,
    RuleStatus,
    SecurityRule,
    Slice,
    VerdictState,
    make_case_id,
    make_finding_id,
)
from agent.steps.lenses import render_questions

QUESTION_SUBJECT = "lenses"


def load_rules(path: Path) -> list[SecurityRule]:
    return [SecurityRule.model_validate(r) for r in yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []]


def _matches(rule: SecurityRule, flow_id: str) -> bool:
    return any(fnmatchcase(flow_id, pattern) for pattern in rule.applies_to)


def build_cases(slices: list[Slice], rules: list[SecurityRule], budget: Budget, *, lenses=(), alerts=()) -> list[Case]:
    cases = []
    for slice_ in slices:
        for rule in rules:
            if rule.status != RuleStatus.approved:
                continue
            for flow in slice_.flows:
                if _matches(rule, flow.flow_id):
                    cases.append(Case(
                        case_id=make_case_id(CaseSource.rule, rule.rule_id, slice_.name, flow.flow_id),
                        source=CaseSource.rule, subject_id=rule.rule_id,
                        question=f"{rule.title} (대상 API: {flow.flow_id})",
                        slice_id=slice_.slice_id, flow_id=flow.flow_id, budget=budget,
                    ))
        if lenses:
            cases.append(Case(
                case_id=make_case_id(CaseSource.question, QUESTION_SUBJECT, slice_.name), source=CaseSource.question,
                subject_id=QUESTION_SUBJECT, question=render_questions(lenses), slice_id=slice_.slice_id, budget=budget,
            ))
    return [*cases, *_alert_cases(slices, alerts, budget)]


def _alert_in_scope(alert: Fact) -> bool:
    cwe = alert.detail.get("cwe")
    return bool(cwe) and cwe not in OUT_OF_SCOPE_CWES


def _slice_for(alert: Fact, slices: list[Slice]) -> Slice | None:
    for slice_ in slices:
        for file in slice_.files:
            if file.path == alert.file and (
                file.ranges is None or alert.line is None or any(a <= alert.line <= b for a, b in file.ranges)
            ):
                return slice_
    return None


def _alert_cases(slices: list[Slice], alerts, budget: Budget) -> list[Case]:
    cases: dict[str, Case] = {}
    for alert in alerts:
        slice_ = _slice_for(alert, slices) if _alert_in_scope(alert) else None
        if slice_ is None:
            continue
        rule = alert.detail.get("rule", "scanner")
        case_id = make_case_id(CaseSource.alert, rule, slice_.name, alert.file)
        where = f"{alert.file}:{alert.line}"
        if case_id in cases:
            cases[case_id].question += f"\n같은 경고의 다른 위치: {where}"
        else:
            cases[case_id] = Case(
                case_id=case_id, source=CaseSource.alert, subject_id=rule, slice_id=slice_.slice_id, budget=budget,
                question=(f"스캐너 경고가 실제 문제인지 코드로 확인하라. 도구 {alert.tool}, 규칙 {rule}, "
                          f"{alert.detail.get('cwe')}, 위치 {where}. 경고 내용: {alert.detail.get('message', '')}"),
            )
    return list(cases.values())


def pass_through_alerts(alerts, slices: list[Slice], failed_case_ids=frozenset()) -> list[Finding]:
    """AI가 판정하지 않는 경고를 도구 결과 그대로 이슈로 만든다.

    탐지 범위 밖이거나 묶음에 없는 위치의 경고, 그리고 AI 조사가 실패한 경고다.
    """
    findings = []
    for alert in alerts:
        slice_ = _slice_for(alert, slices) if _alert_in_scope(alert) else None
        if slice_ is not None:
            case_id = make_case_id(CaseSource.alert, alert.detail.get("rule", "scanner"), slice_.name, alert.file)
            if case_id not in failed_case_ids:
                continue
        rule = alert.detail.get("rule", "scanner")
        message = alert.detail.get("message", rule)
        hops = [Hop(file=alert.file, start=alert.line or 1, end=alert.line or 1, role=Role.sink,
                    quote=alert.detail.get("snippet", ""), certainty=Certainty.tool_confirmed)]
        evidence = EvidencePath(claim=Claim.defect, statement=message, cwe=alert.detail.get("cwe"), hops=hops,
                                basis=[f"{alert.tool} {rule}"])
        findings.append(Finding(
            # 줄 번호 대신 코드 조각으로 ID를 만들어 줄이 밀려도 재검사에서 같은 이슈로 비교된다.
            finding_id=make_finding_id(alert.file, rule, f"{alert.tool}:{alert.detail.get('snippet', '')}"),
            state=VerdictState.unverified,
            root_file=alert.file, broken_rule=rule, cwe=alert.detail.get("cwe"), statement=message, evidence=[evidence],
            outcome=Outcome.warn, tool_confirmed=True,
        ))
    return findings


def _lens_cell(lens, case: Case, result) -> LedgerCell:
    answers = {d.lens_id: d for d in result.dispositions}
    answer = answers.get(lens.lens_id)
    target = case.slice_id
    if answer is None:
        return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.not_seen, reason="답이 없음")
    if answer.disposition == Disposition.no_issue:
        return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.checked, reason="이상을 찾지 못함")
    if answer.disposition == Disposition.not_applicable:
        reason = f"해당 없음: {answer.reason}" if answer.reason else "해당 없음"
        return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.checked, reason=reason)
    if lens.category not in {c.category for c in result.claims}:
        return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.not_seen,
                          reason="문제라고 답했지만 주장이 없음")
    return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.checked, reason="문제 주장 있음")


def update_ledger(ledger: list[LedgerCell], case: Case, result, *, error: str | None = None, lenses=()) -> None:
    target = case.flow_id or case.slice_id
    if case.source == CaseSource.question and result is not None and not error:
        ledger += [_lens_cell(lens, case, result) for lens in lenses]
    elif case.source == CaseSource.question:
        ledger += [LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.not_seen,
                              reason=error or "결과 없음") for lens in lenses]
    elif error or result is None:
        ledger.append(LedgerCell(subject=case.subject_id, target=target, state=LedgerState.not_seen,
                                 reason=error or "결과 없음"))
    else:
        ledger.append(LedgerCell(subject=case.subject_id, target=target, state=LedgerState.checked))
