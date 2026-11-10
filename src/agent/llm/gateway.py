"""모든 LLM 호출이 지나는 한 곳. 비밀값 가리기, 한도 확인, 재시도, 실행 기록을 맡는다."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import openai
from pydantic import BaseModel, ValidationError

from agent.config import AgentConfig, ConfigError
from agent.llm import masking
from agent.schemas.models import Budget, ManifestEntry

CHARS_PER_TOKEN = 3
ATTEMPTS = 2


class SecretLeft(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class LlmFormatError(RuntimeError):
    pass


class LlmCallError(RuntimeError):
    pass


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
        # 로컬 모델은 키가 없어도 되므로 빈 키 대신 자리표시자를 넘긴다.
        self._client = openai.OpenAI(
            base_url=config.base_url, api_key=os.environ.get("OPENAI_API_KEY") or "none", max_retries=0
        )

    def _record(self, entry: ManifestEntry) -> None:
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
            raw = self._client.chat.completions.create(timeout=budget.max_seconds, **kwargs)
        except openai.OpenAIError as e:
            raise LlmCallError(f"LLM 호출 실패: {type(e).__name__}") from e

        usage = raw.usage
        entry.input_tokens += usage.prompt_tokens if usage else 0
        entry.output_tokens += usage.completion_tokens if usage else 0
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
