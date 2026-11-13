import shutil
from pathlib import Path

import pytest
from fake_llm import FakeLlm

from taki.config import AgentConfig

MEMBERS = Path(__file__).parent / "fixtures" / "spring-members"


@pytest.fixture(scope="session")
def extended_app(tmp_path_factory):
    """vulnerable 앱 위에 extended/app을 덮은 앱. 화면·필터·permitAll·가입 API 등을 더했다."""
    root = tmp_path_factory.mktemp("extended") / "app"
    shutil.copytree(MEMBERS / "vulnerable", root)
    shutil.copytree(MEMBERS / "extended" / "app", root, dirs_exist_ok=True)
    return root


@pytest.fixture(autouse=True)
def _no_real_llm_settings(monkeypatch, tmp_path):
    # 시험이 실제 키, 다른 주소, 개발 PC의 .env, LangSmith 전송을 쓰지 못하게 한다.
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    for name in ("LLM_BASE_URL", "LLM_API_KEY", "TAKI_LANGSMITH_PROJECT", "LANGSMITH_API_KEY", "LANGSMITH_TRACING"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("taki.config.ENV_FILE", tmp_path / "no-such.env")


@pytest.fixture
def fake():
    with FakeLlm() as f:
        yield f


def make_config(fake, **overrides) -> AgentConfig:
    models = dict.fromkeys(["onboard", "investigate", "review", "fix"], "fake-model")
    models.update(overrides.pop("models", {}))
    return AgentConfig(base_url=fake.url, models=models, **overrides)
