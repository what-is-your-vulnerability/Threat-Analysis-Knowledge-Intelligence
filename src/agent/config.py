"""실행 설정. 모델 기본값을 두지 않아, 정하지 않은 모델은 호출되지 않는다."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agent.adapters.scanner.semgrep import SemgrepConfig
from agent.schemas.models import Budget

# shortcut: 저장소에서 실행할 때의 위치, 패키지로 배포하면 규칙 파일을 wheel에 포함한다.
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
ROLES = ("onboard", "investigate", "review", "fix")


class ConfigError(ValueError):
    pass


class AgentConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    models: dict[str, str | None] = Field(default_factory=lambda: dict.fromkeys(ROLES))
    budget: Budget = Field(default_factory=Budget)
    reasoning_effort: str | None = None
    # 도구와 추론 강도를 함께 받지 않는 모델용. 정하면 탐색은 이 값으로 하고, 최종 답은 도구 없이 reasoning_effort로 받는다.
    tool_reasoning_effort: str | None = None
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    # LangSmith 프로젝트 이름. 적었을 때만 추적한다(키는 환경변수 LANGSMITH_API_KEY).
    langsmith_project: str | None = None


def load_config(path: Path | None) -> AgentConfig:
    if path is None and Path("agent.yml").exists():
        path = Path("agent.yml")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else {}
    config = AgentConfig.model_validate(data or {})
    if os.environ.get("LLM_BASE_URL"):
        config.base_url = os.environ["LLM_BASE_URL"]
    return config
