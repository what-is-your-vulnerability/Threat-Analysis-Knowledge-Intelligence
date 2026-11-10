"""LLM에게 맡기는 세 역할. 지시는 system 메시지에만 두고, 코드와 문서는 모두 데이터 구간에 넣는다."""

from __future__ import annotations

import json
from fnmatch import fnmatchcase
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agent.config import RULES_DIR
from agent.llm.gateway import LlmGateway
from agent.llm.tool_loop import run_tool_loop, wrap_data
from agent.schemas.models import (
    Case,
    EvidencePath,
    FixProposal,
    LensDisposition,
    Review,
    ReviewResult,
    RuleStatus,
    SecurityRule,
)

PROMPT_DIR = Path(__file__).parent / "prompts"


class InvestigateResult(BaseModel):
    claims: list[EvidencePath] = Field(default_factory=list)
    dispositions: list[LensDisposition] = Field(default_factory=list)


class _ReviewOutput(BaseModel):
    # evidence_check는 프로그램이 채우는 칸이므로 LLM 응답에서 받지 않는다.
    result: ReviewResult
    reason: str = ""
    evidence: EvidencePath | None = None


class _RuleDraft(BaseModel):
    # status와 rule_id는 LLM에게 받지 않는다. 규칙은 항상 사람 승인을 기다리는 상태로 시작한다.
    title: str
    requirement_quote: str
    doc_ref: str | None = None
    stride: list[str] = Field(default_factory=list)
    category: int | None = None
    cwe: str | None = None
    standard_ref: str | None = None
    applies_to: list[str] = Field(default_factory=list)


class _CategoryNote(BaseModel):
    category: int
    reason: str


class _Threat(BaseModel):
    feature: str
    stride: str
    threat: str


class _DeriveOutput(BaseModel):
    threats: list[_Threat] = Field(default_factory=list)
    rules: list[_RuleDraft] = Field(default_factory=list)
    category_notes: list[_CategoryNote] = Field(default_factory=list)


class DerivedRules(list):
    """승인 대기 규칙 목록. 버린 후보와 빠진 범주는 warnings에 남는다."""

    def __init__(self):
        super().__init__()
        self.warnings: list[str] = []
        self.category_notes: dict[int, str] = {}
        self.threats: list[dict] = []


def _messages(version: str, *blocks: str) -> list[dict]:
    system = (PROMPT_DIR / f"{version}.md").read_text(encoding="utf-8")
    return [{"role": "system", "content": system}, {"role": "user", "content": "\n\n".join(blocks)}]


def _claim_for_reader(evidence: EvidencePath) -> str:
    # 재검토자가 조사자의 추론에 끌려가지 않도록 주장과 인용만 전달한다.
    shown = evidence.model_dump(mode="json", include={"claim", "statement", "cwe", "category", "hops", "root_symbol",
                                                      "expected_positions", "basis"})
    return json.dumps(shown, ensure_ascii=False, indent=1)


def investigate(
    case: Case,
    slice_text: str,
    *,
    gateway: LlmGateway,
    requirement: str | None = None,
    tools=None,
    sent_files: list[str] | None = None,
    feedback: str | None = None,
) -> InvestigateResult:
    blocks = [wrap_data("QUESTION", case.question)]
    if requirement:
        blocks.append(wrap_data("REQUIREMENT", requirement))
    blocks.append(wrap_data("CODE", slice_text))
    if feedback:
        blocks.append(feedback)
    if tools is not None:
        return run_tool_loop(
            "investigate", _messages("investigate_v1", *blocks), prompt_version="investigate_v1",
            schema=InvestigateResult, tools=tools, gateway=gateway, budget=case.budget, case_id=case.case_id,
            sent_files=sent_files,
        )
    response = gateway.complete(
        "investigate", _messages("investigate_v1", *blocks), prompt_version="investigate_v1",
        schema=InvestigateResult, budget=case.budget, case_id=case.case_id, sent_files=sent_files,
    )
    return response.parsed


def review(
    evidence: EvidencePath,
    slice_text: str,
    *,
    view: str = "defense",
    gateway: LlmGateway,
    tools=None,
    case_id: str | None = None,
    sent_files: list[str] | None = None,
) -> Review:
    blocks = [f"관점: {view}", wrap_data("CLAIM", _claim_for_reader(evidence)), wrap_data("CODE", slice_text)]
    if tools is not None:
        out = run_tool_loop(
            "review", _messages("review_v1", *blocks), prompt_version="review_v1", schema=_ReviewOutput, tools=tools,
            gateway=gateway, budget=None, case_id=case_id, sent_files=sent_files,
        )
        return Review(result=out.result, reason=out.reason, evidence=out.evidence)
    response = gateway.complete(
        "review", _messages("review_v1", *blocks), prompt_version="review_v1", schema=_ReviewOutput,
        case_id=case_id, sent_files=sent_files,
    )
    out = response.parsed
    return Review(result=out.result, reason=out.reason, evidence=out.evidence)


def propose_fix(
    evidence: EvidencePath,
    slice_text: str,
    *,
    gateway: LlmGateway,
    case_id: str | None = None,
    sent_files: list[str] | None = None,
) -> FixProposal:
    blocks = [wrap_data("CLAIM", _claim_for_reader(evidence)), wrap_data("CODE", slice_text)]
    response = gateway.complete(
        "fix", _messages("fix_v1", *blocks), prompt_version="fix_v1", schema=FixProposal,
        case_id=case_id, sent_files=sent_files,
    )
    return response.parsed


def load_templates() -> list[dict]:
    return yaml.safe_load((RULES_DIR / "templates.yml").read_text(encoding="utf-8"))


def _squeeze(text: str) -> str:
    return " ".join(text.split())


def derive_rules(design_docs, entrypoints: list[str], templates: list[dict], *, gateway: LlmGateway) -> DerivedRules:
    """설계문서에서 보안 규칙 후보를 뽑는다. 문서에 없는 인용은 버리고, 결과는 모두 승인 대기로 시작한다."""
    texts = {Path(d).name: Path(d).read_text(encoding="utf-8", errors="replace") for d in design_docs}
    blocks = [wrap_data(f"DESIGN {name}", text) for name, text in texts.items()]
    blocks.append(wrap_data("ENTRYPOINTS", "\n".join(entrypoints)))
    blocks.append(wrap_data("TEMPLATES", json.dumps(templates, ensure_ascii=False)))
    response = gateway.complete("onboard", _messages("onboard_v1", *blocks), prompt_version="onboard_v1",
                                schema=_DeriveOutput, sent_files=list(texts))
    output = response.parsed

    derived = DerivedRules()
    derived.threats = [t.model_dump() for t in output.threats]
    derived.category_notes = {n.category: n.reason for n in output.category_notes}
    known = {t["id"] for t in templates}
    documents = _squeeze("\n".join(texts.values()))
    for draft in output.rules:
        if _squeeze(draft.requirement_quote) not in documents:
            derived.warnings.append(f"문서에 없는 인용이라 뺌: {draft.requirement_quote}")
            continue
        if not any(fnmatchcase(e, p) for e in entrypoints for p in draft.applies_to):
            derived.warnings.append(f"맞는 API가 없는 규칙: {draft.title} {draft.applies_to}")
        derived.append(SecurityRule(
            rule_id=f"R{len(derived) + 1}", status=RuleStatus.pending, version=1,
            out_of_standard=draft.standard_ref not in known, **draft.model_dump(),
        ))
    covered = {r.category for r in derived} | set(derived.category_notes)
    derived.warnings += [f"범주 {c}: 규칙도 해당 없음 이유도 없음" for c in range(1, 9) if c not in covered]
    return derived


def renumber_after(used_ids, derived: list[SecurityRule]) -> list[SecurityRule]:
    """새 후보의 ID를 이미 쓴 ID 뒤로 매긴다. 한 프로젝트에서 규칙 ID가 겹치면 조사 항목 ID도 겹친다."""
    numbers = [int(i[1:]) for i in used_ids if i[:1] == "R" and i[1:].isdigit()]
    start = max(numbers, default=0)
    return [rule.model_copy(update={"rule_id": f"R{start + n}"}) for n, rule in enumerate(derived, start=1)]
