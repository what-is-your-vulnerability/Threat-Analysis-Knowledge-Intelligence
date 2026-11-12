"""LangSmith로 보내는 기록의 경계.

LLM 호출 기록(가린 메시지·응답)만 그대로 두고, 그래프 단계 기록은 코드 없이 줄인다.
"""

from __future__ import annotations

from pathlib import Path

from langsmith import Client

from taki.schemas.models import Case, Slice

# 단계 기록에 그대로 남겨도 되는 글자 값. 코드·인용·프롬프트가 들어가는 키는 넣지 않는다.
SAFE_TEXT_KEYS = frozenset(
    {
        "case_id",
        "source",
        "subject",
        "subject_id",
        "question",
        "slice",
        "flow",
        "flow_id",
        "state",
        "reason",
        "claim_key",
        "error",
        "mode",
        "role",
        "name",
    }
)


def is_llm_payload(data: dict) -> bool:
    """wrap_openai가 남기는 LLM 호출 입력(messages+model)과 출력(choices)인지 본다."""
    return ("messages" in data and "model" in data) or "choices" in data


def _brief(key: str, value):
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Case):
        return value.case_id
    if isinstance(value, Slice):
        return value.name
    if isinstance(value, Path):
        return value.name
    if isinstance(value, str):
        return value if key in SAFE_TEXT_KEYS else f"<{len(value)}자>"
    if isinstance(value, list | tuple | dict | set):
        return f"{len(value)}개"
    return f"<{type(value).__name__}>"


def hide_payload(data: dict) -> dict:
    if not isinstance(data, dict) or is_llm_payload(data):
        return data
    return {key: _brief(key, value) for key, value in data.items()}


def trace_client() -> Client:
    return Client(hide_inputs=hide_payload, hide_outputs=hide_payload)
