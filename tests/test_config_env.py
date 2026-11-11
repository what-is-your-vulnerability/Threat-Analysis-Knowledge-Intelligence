"""키는 agent/.env로 관리한다. 셸에 이미 있는 값이 먼저다."""

import os

import pytest

from taki import config as config_module
from taki.config import load_config

ENV_TEXT = """# 주석
export OPENAI_API_KEY="sk-from-file"
LANGSMITH_API_KEY='ls-from-file'
TAKI_LANGSMITH_PROJECT = taki

NOT_A_PAIR
LLM_API_KEY=
"""


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(ENV_TEXT, encoding="utf-8")
    monkeypatch.setattr(config_module, "ENV_FILE", path)
    monkeypatch.setattr(os, "environ", {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"})
    monkeypatch.chdir(tmp_path)
    return path


def test_env_file_is_loaded(env_file):
    config = load_config(None)
    assert os.environ["OPENAI_API_KEY"] == "sk-from-file" and os.environ["LANGSMITH_API_KEY"] == "ls-from-file"
    assert config.langsmith_project == "taki"
    assert "LLM_API_KEY" not in os.environ  # 빈 값은 설정하지 않은 것으로 본다


def test_shell_value_wins_over_env_file(env_file):
    os.environ["OPENAI_API_KEY"] = "sk-from-shell"
    load_config(None)
    assert os.environ["OPENAI_API_KEY"] == "sk-from-shell"


def test_generic_langsmith_project_does_not_turn_tracing_on(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LANGSMITH_PROJECT", "other-project")
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    assert load_config(None).langsmith_project is None
