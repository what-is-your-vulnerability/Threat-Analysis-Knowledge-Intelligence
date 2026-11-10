"""실행 설정. 모델 기본값을 두지 않아, 정하지 않은 모델은 호출되지 않는다."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from agent.adapters.scanner.docker import ScannerSpec, load_scanner
from agent.errors import ConfigError
from agent.schemas.models import Budget

# shortcut: 저장소에서 실행할 때의 위치, 패키지로 배포하면 규칙 파일을 wheel에 포함한다.
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
ROLES = ("onboard", "investigate", "review", "fix")
ENV_FILE = Path(".env")  # 실행한 폴더의 .env. 키는 커밋하지 않는다.


class AgentConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    models: dict[str, str | None] = Field(default_factory=lambda: dict.fromkeys(ROLES))
    budget: Budget = Field(default_factory=Budget)
    reasoning_effort: str | None = None
    # 도구와 추론 강도를 함께 받지 않는 모델용. 정하면 탐색은 이 값으로 하고, 최종 답은 도구 없이 reasoning_effort로 받는다.
    tool_reasoning_effort: str | None = None
    # 먼저 돌릴 SAST 도구. 이름(rules/scanners/<이름>.yml)이나 직접 쓴 정의. 비어 있으면 돌리지 않는다.
    scanners: list[ScannerSpec] = Field(default_factory=list)
    # LangSmith 프로젝트 이름. 적었을 때만 추적한다(키는 환경변수 LANGSMITH_API_KEY).
    langsmith_project: str | None = None

    @field_validator("scanners", mode="before")
    @classmethod
    def _load_scanners(cls, value):
        # 직접 쓴 정의의 상대 경로는 실행한 폴더 기준이다.
        return [load_scanner(entry, Path.cwd()) for entry in value or []]


def load_env_file(path: Path) -> None:
    """KEY=VALUE 줄을 환경변수로 읽는다. 셸에 이미 있는 값은 덮지 않는다."""
    # shortcut: 따옴표 밖의 줄 끝 주석과 ${...} 치환은 지원하지 않는다. 필요해지면 python-dotenv로 바꾼다.
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key or not value or key.startswith("#"):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def load_config(path: Path | None) -> AgentConfig:
    load_env_file(ENV_FILE)
    if path is None and Path("agent.yml").exists():
        path = Path("agent.yml")
    data = (yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else {}) or {}
    if "semgrep" in data:
        raise ConfigError("semgrep 설정은 scanners로 옮겼습니다. 예: scanners: [semgrep]")
    try:
        config = AgentConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"설정 파일 오류: {e}") from e
    if os.environ.get("LLM_BASE_URL"):
        config.base_url = os.environ["LLM_BASE_URL"]
    # 다른 프로젝트용으로 흔히 켜 두는 LANGSMITH_PROJECT가 아니라 이 Agent 전용 변수로만 추적을 켠다.
    if os.environ.get("SECAGENT_LANGSMITH_PROJECT"):
        config.langsmith_project = os.environ["SECAGENT_LANGSMITH_PROJECT"]
    return config
