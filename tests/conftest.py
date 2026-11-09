import pytest
from fake_llm import FakeLlm

from agent.config import AgentConfig


@pytest.fixture(autouse=True)
def _no_real_llm_settings(monkeypatch):
    # 시험이 실제 키나 다른 주소를 쓰지 못하게 한다.
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)


@pytest.fixture
def fake():
    with FakeLlm() as f:
        yield f


def make_config(fake, **overrides) -> AgentConfig:
    models = dict.fromkeys(["onboard", "investigate", "review", "fix"], "fake-model")
    models.update(overrides.pop("models", {}))
    return AgentConfig(base_url=fake.url, models=models, **overrides)
