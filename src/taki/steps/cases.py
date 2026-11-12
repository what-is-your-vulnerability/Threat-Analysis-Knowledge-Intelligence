"""보안 규칙과 기능 묶음에서 조사 항목을 만들고, 무엇을 봤는지 기록한다."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from taki.schemas.models import (
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
from taki.steps.lenses import render_questions

QUESTION_SUBJECT = "lenses"
# 탐지 범위(docs/detection-scope.md, 2026-11-05 고정) 안의 CWE만 AI가 확인한다. 나머지 경고는 도구 결과로만 싣는다.
IN_SCOPE_CWES = {
    "CWE-89",
    "CWE-943",
    "CWE-306",
    "CWE-862",
    "CWE-285",
    "CWE-639",
    "CWE-200",
    "CWE-213",
    "CWE-532",
    "CWE-209",
    "CWE-312",
    "CWE-916",
    "CWE-328",
    "CWE-319",
    "CWE-915",
    "CWE-602",
    "CWE-841",
    "CWE-840",
    "CWE-20",
    "CWE-798",
    "CWE-321",
    "CWE-347",
    "CWE-79",
}


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
                    cases.append(
                        Case(
                            case_id=make_case_id(CaseSource.rule, rule.rule_id, slice_.name, flow.flow_id),
                            source=CaseSource.rule,
                            subject_id=rule.rule_id,
                            question=f"{rule.title} (대상 API: {flow.flow_id})",
                            slice_id=slice_.slice_id,
                            flow_id=flow.flow_id,
                            budget=budget,
                        )
                    )
        if lenses:
            cases.append(
                Case(
                    case_id=make_case_id(CaseSource.question, QUESTION_SUBJECT, slice_.name),
                    source=CaseSource.question,
                    subject_id=QUESTION_SUBJECT,
                    question=render_questions(lenses),
                    slice_id=slice_.slice_id,
                    budget=budget,
                )
            )
    return [*cases, *_alert_cases(slices, alerts, budget)]


def _alert_in_scope(alert: Fact) -> bool:
    return alert.detail.get("cwe") in IN_SCOPE_CWES


def _slice_for(alert: Fact, slices: list[Slice]) -> Slice | None:
    for slice_ in slices:
        for file in slice_.files:
            if file.path == alert.file and (
                file.ranges is None or alert.line is None or any(a <= alert.line <= b for a, b in file.ranges)
            ):
                return slice_
    return None


def alert_case_id(alert: Fact, slice_: Slice) -> str:
    """같은 파일·같은 CWE 경고는 도구와 줄이 달라도 조사 항목 하나로 본다."""
    return make_case_id(CaseSource.alert, alert.detail["cwe"], slice_.name, alert.file)


def _alert_line(alert: Fact) -> str:
    line = (
        f"- 도구 {alert.tool}, 규칙 {alert.detail.get('rule', 'scanner')}, 위치 {alert.file}:{alert.line}, "
        f"내용 {alert.detail.get('message', '')}"
    )
    return line + (f", 경로 {' -> '.join(alert.detail['flow'])}" if alert.detail.get("flow") else "")


def _alert_cases(slices: list[Slice], alerts, budget: Budget) -> list[Case]:
    cases: dict[str, Case] = {}
    for alert in alerts:
        slice_ = _slice_for(alert, slices) if _alert_in_scope(alert) else None
        if slice_ is None:
            continue
        case_id = alert_case_id(alert, slice_)
        if case_id not in cases:
            cwe = alert.detail["cwe"]
            cases[case_id] = Case(
                case_id=case_id,
                source=CaseSource.alert,
                subject_id=cwe,
                slice_id=slice_.slice_id,
                budget=budget,
                question=f"스캐너 경고가 실제 문제인지 코드로 확인하라. {cwe}, 파일 {alert.file}.",
            )
        cases[case_id].question += "\n" + _alert_line(alert)
    return list(cases.values())


def alerts_by_slice(alerts, slices: list[Slice]) -> dict[str, list[Fact]]:
    """조사 자료로 보여 줄 경고. 탐지 범위 안이고 묶음에 든 위치만 묶음별로 모은다."""
    grouped: dict[str, list[Fact]] = {}
    for alert in alerts:
        slice_ = _slice_for(alert, slices) if _alert_in_scope(alert) else None
        if slice_ is not None:
            grouped.setdefault(slice_.slice_id, []).append(alert)
    return grouped


def _flow_hops(alert: Fact) -> list[Hop]:
    """도구 데이터 흐름("file:line")의 앞 단계들. 마지막 단계는 경고 위치(싱크)와 같아 뺀다."""
    hops = []
    for step in alert.detail.get("flow", [])[:-1]:
        file, _, line = step.rpartition(":")
        if line.isdigit():  # 줄 번호가 없는 단계("file:None")는 위치를 지어내지 않고 뺀다
            hops.append(
                Hop(
                    file=file,
                    start=int(line),
                    end=int(line),
                    quote="",
                    role=Role.propagation,
                    certainty=Certainty.tool_confirmed,
                )
            )
    return hops


def pass_through_alerts(alerts, slices: list[Slice], failed_case_ids=frozenset()) -> list[Finding]:
    """AI가 판정하지 않는 경고를 도구 결과 그대로 이슈로 만든다.

    탐지 범위 밖이거나 묶음에 없는 위치의 경고, 그리고 AI 조사가 실패한 경고다.
    """
    findings = []
    for alert in alerts:
        slice_ = _slice_for(alert, slices) if _alert_in_scope(alert) else None
        if slice_ is not None and alert_case_id(alert, slice_) not in failed_case_ids:
            continue
        rule = alert.detail.get("rule", "scanner")
        message = alert.detail.get("message", rule)
        hops = [
            *_flow_hops(alert),
            Hop(
                file=alert.file,
                start=alert.line or 1,
                end=alert.line or 1,
                role=Role.sink,
                quote=alert.detail.get("snippet", ""),
                certainty=Certainty.tool_confirmed,
            ),
        ]
        evidence = EvidencePath(
            claim=Claim.defect,
            statement=message,
            cwe=alert.detail.get("cwe"),
            hops=hops,
            basis=[f"{alert.tool} {rule}"],
        )
        findings.append(
            Finding(
                # 줄 번호 대신 코드 조각으로 ID를 만들어 줄이 밀려도 재검사에서 같은 이슈로 비교된다.
                finding_id=make_finding_id(alert.file, rule, f"{alert.tool}:{alert.detail.get('snippet', '')}"),
                state=VerdictState.unverified,
                root_file=alert.file,
                broken_rule=rule,
                cwe=alert.detail.get("cwe"),
                statement=message,
                evidence=[evidence],
                outcome=Outcome.warn,
                tool_confirmed=True,
            )
        )
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
        return LedgerCell(
            subject=lens.lens_id, target=target, state=LedgerState.not_seen, reason="문제라고 답했지만 주장이 없음"
        )
    return LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.checked, reason="문제 주장 있음")


def update_ledger(ledger: list[LedgerCell], case: Case, result, *, error: str | None = None, lenses=()) -> None:
    target = case.flow_id or case.slice_id
    if case.source == CaseSource.question and result is not None and not error:
        ledger += [_lens_cell(lens, case, result) for lens in lenses]
    elif case.source == CaseSource.question:
        ledger += [
            LedgerCell(subject=lens.lens_id, target=target, state=LedgerState.not_seen, reason=error or "결과 없음")
            for lens in lenses
        ]
    elif error or result is None:
        ledger.append(
            LedgerCell(subject=case.subject_id, target=target, state=LedgerState.not_seen, reason=error or "결과 없음")
        )
    else:
        ledger.append(LedgerCell(subject=case.subject_id, target=target, state=LedgerState.checked))
