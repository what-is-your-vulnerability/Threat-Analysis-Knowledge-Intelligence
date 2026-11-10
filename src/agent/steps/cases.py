"""보안 규칙과 기능 묶음에서 조사 항목을 만들고, 무엇을 봤는지 기록한다."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from agent.schemas.models import (
    Budget,
    Case,
    CaseSource,
    LedgerCell,
    LedgerState,
    RuleStatus,
    SecurityRule,
    Slice,
    make_case_id,
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
    return cases


def update_ledger(ledger: list[LedgerCell], case: Case, result, *, error: str | None = None) -> None:
    target = case.flow_id or case.slice_id
    if error or result is None:
        ledger.append(LedgerCell(subject=case.subject_id, target=target, state=LedgerState.not_seen,
                                 reason=error or "결과 없음"))
    else:
        ledger.append(LedgerCell(subject=case.subject_id, target=target, state=LedgerState.checked))
