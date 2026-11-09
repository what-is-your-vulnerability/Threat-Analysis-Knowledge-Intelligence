"""LLM에게 맡기는 세 역할. 지시는 system 메시지에만 두고, 코드와 문서는 모두 데이터 구간에 넣는다."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from agent.llm.gateway import LlmGateway
from agent.schemas.models import Case, EvidencePath, FixProposal, LensDisposition, Review, ReviewResult

PROMPT_DIR = Path(__file__).parent / "prompts"


class InvestigateResult(BaseModel):
    claims: list[EvidencePath] = Field(default_factory=list)
    dispositions: list[LensDisposition] = Field(default_factory=list)


class _ReviewOutput(BaseModel):
    # evidence_check는 프로그램이 채우는 칸이므로 LLM 응답에서 받지 않는다.
    result: ReviewResult
    reason: str = ""
    evidence: EvidencePath | None = None


def wrap_data(label: str, text: str) -> str:
    return f"<<<DATA {label}>>>\n{text.replace('<<<', '<<\\<')}\n<<<END DATA>>>"


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
