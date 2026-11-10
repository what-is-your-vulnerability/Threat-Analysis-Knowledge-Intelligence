"""조사 항목 하나를 맡는 그래프. 조사 → 근거 확인 → (인용을 못 찾으면 한 번 다시 조사) → 재검토·판정."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from agent.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from agent.llm.roles import investigate, review
from agent.schemas.models import (
    Case,
    CaseSource,
    CheckFailure,
    Claim,
    EvidenceCheck,
    EvidencePath,
    Fact,
    Flow,
    LedgerCell,
    Review,
    ReviewResult,
    SecurityRule,
    Slice,
    Snapshot,
    Verdict,
)
from agent.steps.cases import update_ledger
from agent.steps.evidence import check_evidence
from agent.steps.slices import render_slice
from agent.steps.verdict import decide
from agent.tools.readonly import ReadOnlyTools

LLM_ERRORS = (LlmCallError, LlmFormatError, BudgetExceeded, SecretLeft)
QUOTE_FAILURES = {CheckFailure.quote_not_found, CheckFailure.quote_ambiguous}


@dataclass
class ScanRuntime:
    """검사 한 번 동안 함께 쓰는 실행 도구. 그래프 상태에 두되 LangSmith 기록에는 타입 이름만 남는다."""
    gateway: LlmGateway
    reader: ReadOnlyTools
    index: Any
    mappers: Any
    spring: Any
    lenses: list


class CaseState(TypedDict, total=False):
    case: Any
    slice_: Any
    rule: Any
    snapshot: Any
    runtime: Any
    slice_text: str  # 조사에 보내는 묶음 글(정적분석 경고 포함)
    review_text: str  # 재검토에 보내는 묶음 글(경고 없음). 재검토가 도구 결과에 끌려가지 않게 한다
    requirement: str | None
    sent: list[str]
    result: Any
    feedback: str | None
    retried: bool
    error: str | None
    verdicts: list
    ledger: list


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


def _review_claim(claim, check, state: CaseState, flows) -> Review:
    runtime, case = state["runtime"], state["case"]
    fixed = claim.model_copy(update={"hops": check.fixed_hops})
    try:
        result = review(fixed, state["review_text"], gateway=runtime.gateway, case_id=case.case_id,
                        sent_files=state["sent"], tools=runtime.reader)
    except LLM_ERRORS as e:
        return Review(result=ReviewResult.not_proven, reason=f"재검토 호출 실패: {e}")
    if result.result == ReviewResult.refuted and result.evidence:
        result.evidence_check = check_evidence(result.evidence, state["snapshot"], flows)
    return result


def _investigate(state: CaseState) -> dict:
    runtime = state["runtime"]
    try:
        result = investigate(state["case"], state["slice_text"], gateway=runtime.gateway,
                             requirement=state["requirement"], sent_files=state["sent"], tools=runtime.reader,
                             feedback=state["feedback"])
    except LLM_ERRORS as e:
        return {"error": str(e)}
    return {"result": result}


def _check(state: CaseState) -> dict:
    if state["retried"]:
        return {"feedback": None}
    claims = state["result"].claims
    checks = [check_evidence(c, state["snapshot"], _flows_for(state["case"], state["slice_"], c)) for c in claims]
    if any(QUOTE_FAILURES & set(c.failures) for c in checks):
        return {"feedback": _quote_feedback(claims, checks), "retried": True}
    return {"feedback": None}


def _fail(state: CaseState) -> dict:
    case, error = state["case"], state["error"]
    ledger: list[LedgerCell] = []
    update_ledger(ledger, case, None, error=error, lenses=state["runtime"].lenses)
    return {"ledger": ledger, "verdicts": [decide(case.case_id, None, None, [], state["slice_"].code_hash, error=error)]}


def _decide(state: CaseState) -> dict:
    case, slice_, result = state["case"], state["slice_"], state["result"]
    ledger: list[LedgerCell] = []
    if case.source == CaseSource.question:
        # 답만 있고 주장이 없으면 판정을 만들지 않는다. "이상을 찾지 못함"은 구현 확인이 아니다.
        update_ledger(ledger, case, result, lenses=state["runtime"].lenses)
    else:
        update_ledger(ledger, case, result, error=None if result.claims else "주장이 없음")
        if not result.claims:
            return {"ledger": ledger, "verdicts": [decide(case.case_id, None, None, [], slice_.code_hash)]}
    verdicts: list[Verdict] = []
    for claim in result.claims:
        flows = _flows_for(case, slice_, claim)
        check = check_evidence(claim, state["snapshot"], flows)
        reviews = []
        if check.passed and claim.claim in (Claim.absent, Claim.defect):
            reviews.append(_review_claim(claim, check, state, flows))
        verdicts.append(decide(case.case_id, claim, check, reviews, slice_.code_hash))
    return {"ledger": ledger, "verdicts": verdicts}


def _build():
    graph = StateGraph(CaseState)
    graph.add_node("investigate", _investigate)
    graph.add_node("check", _check)
    graph.add_node("fail", _fail)
    graph.add_node("decide", _decide)
    graph.add_edge(START, "investigate")
    graph.add_conditional_edges("investigate", lambda s: "fail" if s["error"] else "check", ["fail", "check"])
    graph.add_conditional_edges("check", lambda s: "investigate" if s["feedback"] else "decide", ["investigate", "decide"])
    graph.add_edge("fail", END)
    graph.add_edge("decide", END)
    return graph.compile()


CASE_GRAPH = _build()


def run_case(case: Case, slice_: Slice, rule: SecurityRule | None, snapshot: Snapshot, runtime: ScanRuntime,
             alerts: Sequence[Fact] = ()) -> tuple[list[Verdict], list[LedgerCell]]:
    review_text = render_slice(slice_, snapshot)
    state: CaseState = {
        "case": case, "slice_": slice_, "rule": rule, "snapshot": snapshot, "runtime": runtime,
        "slice_text": render_slice(slice_, snapshot, alerts) if alerts else review_text, "review_text": review_text,
        "requirement": f"{rule.doc_ref}: {rule.requirement_quote}" if rule and rule.requirement_quote else None,
        "sent": [f.path for f in slice_.files], "result": None, "feedback": None, "retried": False, "error": None,
        "verdicts": [], "ledger": [],
    }
    final = CASE_GRAPH.invoke(state, {"run_name": f"조사 항목 {case.case_id}"})
    for verdict in final["verdicts"]:
        verdict.manifest_ids = list(runtime.gateway.manifest_ids_by_case.get(case.case_id, []))
    return final["verdicts"], final["ledger"]
