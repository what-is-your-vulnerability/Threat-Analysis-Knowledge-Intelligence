"""모든 LLM 호출이 지나는 한 곳. 비밀값 가리기, 한도 확인, 재시도, 실행 기록을 맡는다."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import openai
from langsmith.wrappers import wrap_openai
from pydantic import BaseModel, ValidationError

from taki.config import AgentConfig, ConfigError
from taki.llm import masking
from taki.schemas.models import Budget, ManifestEntry

OPENAI_HOST = "api.openai.com"
CHARS_PER_TOKEN = 3
ATTEMPTS = 2


class SecretLeft(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class LlmFormatError(RuntimeError):
    pass


class OutputLimitExceeded(LlmFormatError):
    """답을 쓰다가 출력 한도에서 잘렸다. 같은 한도로 다시 보내도 같으므로 재시도하지 않는다."""


class ReasoningRunaway(LlmFormatError):
    """추론만 하다 답 없이 한도에 걸렸다. 무작위로 생기므로 한 번 더 보낸다."""


class LlmCallError(RuntimeError):
    pass


def _api_key(base_url: str) -> str:
    # OpenAI 키는 OpenAI로만 보낸다. 다른 주소에 쓸 키는 LLM_API_KEY로 따로 받고, 로컬 모델은 없어도 된다.
    if urlsplit(base_url).hostname == OPENAI_HOST:
        return os.environ.get("OPENAI_API_KEY") or "none"
    return os.environ.get("LLM_API_KEY") or "none"


@dataclass
class LlmResponse:
    content: str | None
    parsed: BaseModel | None
    tool_calls: list[dict] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    manifest_id: str = ""


class LlmGateway:
    def __init__(self, config: AgentConfig, run_dir: Path):
        self.config = config
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_ids_by_case: dict[str, list[str]] = {}
        client = openai.OpenAI(base_url=config.base_url, api_key=_api_key(config.base_url), max_retries=0)
        # 설정으로 켰을 때만 감싼다. 감싼 클라이언트는 가린 뒤의 메시지만 받는다.
        self._traced = bool(config.langsmith_project)
        self._client = wrap_openai(client) if self._traced else client

    def _record(self, entry: ManifestEntry) -> None:
        if entry.case_id:
            self.manifest_ids_by_case.setdefault(entry.case_id, []).append(entry.manifest_id)
        with (self.run_dir / "manifest.jsonl").open("a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

    def complete(
        self,
        role: str,
        messages: list[dict],
        *,
        prompt_version: str,
        schema: type[BaseModel] | None = None,
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        case_id: str | None = None,
        sent_files: list[str] | None = None,
        reasoning_effort: str | None = None,
    ) -> LlmResponse:
        budget = budget or self.config.budget
        model = self.config.models.get(role)
        if not model:
            raise ConfigError(f"역할 '{role}'의 모델이 정해지지 않았습니다.")

        entry = ManifestEntry(
            manifest_id=uuid.uuid4().hex[:16], role=role, model=model, prompt_version=prompt_version,
            case_id=case_id, sent_files=sent_files or [],
        )
        masked = [self._mask_message(m) for m in messages]
        texts = [m["content"] for m in masked if isinstance(m.get("content"), str)]
        left = sorted({name for t in texts for name in masking.find_secrets(t)})
        if left:
            entry.error = f"가리지 못한 값: {left}"
            self._record(entry)  # 원문이 남지 않도록 메시지는 기록하지 않는다.
            raise SecretLeft(entry.error)

        entry.messages = masked
        estimate = sum(len(t) for t in texts) // CHARS_PER_TOKEN
        if estimate > budget.max_input_tokens:
            entry.error = f"입력 한도 초과: 약 {estimate} 토큰"
            self._record(entry)
            raise BudgetExceeded(entry.error)

        kwargs: dict = {"model": model, "messages": masked, "max_completion_tokens": budget.max_output_tokens}
        effort = reasoning_effort or self.config.reasoning_effort
        if effort:
            kwargs["reasoning_effort"] = effort
        if tools:
            kwargs["tools"] = tools
        if schema:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema()},
            }

        started = time.monotonic()
        error: Exception | None = None
        response = None
        for _ in range(ATTEMPTS):
            try:
                response = self._send(kwargs, schema, budget, entry)
                error = None
                break
            except OutputLimitExceeded as e:
                error = e
                break
            except (LlmCallError, LlmFormatError) as e:
                error = e
        entry.seconds = round(time.monotonic() - started, 3)
        if error:
            entry.error = str(error)
            self._record(entry)
            raise error
        response.manifest_id = entry.manifest_id
        entry.tool_calls = [c["name"] for c in response.tool_calls]
        self._record(entry)
        return response

    @staticmethod
    def _mask_message(message: dict) -> dict:
        content = message.get("content")
        return {**message, "content": masking.mask_text(content).text} if isinstance(content, str) else dict(message)

    def _send(self, kwargs: dict, schema, budget: Budget, entry: ManifestEntry) -> LlmResponse:
        try:
            extra = {"langsmith_extra": {
                "name": f"{entry.role} {entry.prompt_version}", "tags": [entry.role],
                "metadata": {"case_id": entry.case_id, "prompt_version": entry.prompt_version, "manifest_id": entry.manifest_id},
            }} if self._traced else {}
            raw = self._client.chat.completions.create(timeout=budget.max_seconds, **kwargs, **extra)
        except openai.OpenAIError as e:
            raise LlmCallError(f"LLM 호출 실패: {type(e).__name__}") from e

        usage = raw.usage
        entry.input_tokens += usage.prompt_tokens if usage else 0
        entry.output_tokens += usage.completion_tokens if usage else 0
        if raw.choices[0].finish_reason == "length":
            limit = f"출력 한도 {budget.max_output_tokens} 토큰"
            if not raw.choices[0].message.content:
                raise ReasoningRunaway(f"{limit}에 걸려 답이 비어 있음")
            raise OutputLimitExceeded(f"{limit}에서 응답이 잘림")
        message = raw.choices[0].message
        tool_calls = [
            {"id": c.id, "name": c.function.name, "arguments": c.function.arguments} for c in message.tool_calls or []
        ]
        parsed = None
        if schema and not tool_calls:
            try:
                parsed = schema.model_validate(json.loads(message.content or ""))
            except (json.JSONDecodeError, ValidationError) as e:
                raise LlmFormatError(f"응답 형식 오류: {type(e).__name__}") from e
        return LlmResponse(content=message.content, parsed=parsed, tool_calls=tool_calls,
                           usage={"input": entry.input_tokens, "output": entry.output_tokens})
