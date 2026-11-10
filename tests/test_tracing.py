"""LangSmith 추적은 설정으로 켰을 때만 동작한다. 기록 내용의 경계는 test_trace_boundary.py가 본다."""

import contextlib
import json
from pathlib import Path

from conftest import make_config
from langsmith import Client

from agent.config import AgentConfig
from agent.core import orchestrator
from agent.llm import gateway as gateway_module
from agent.llm.gateway import LlmGateway
from agent.schemas.models import Budget

FIX = Path(__file__).parent / "fixtures" / "spring-members"


def _spy_wrapper(monkeypatch):
    calls = []

    def spy(client, **kwargs):
        calls.append(client)
        return client

    monkeypatch.setattr(gateway_module, "wrap_openai", spy)
    return calls


def test_tracing_is_off_by_default(fake, tmp_path, monkeypatch):
    calls = _spy_wrapper(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING", "true")  # 셸에 켜져 있어도 설정이 없으면 감싸지 않는다
    LlmGateway(make_config(fake), tmp_path)
    assert AgentConfig().langsmith_project is None and calls == []


def test_project_setting_wraps_the_client(fake, tmp_path, monkeypatch):
    calls = _spy_wrapper(monkeypatch)
    LlmGateway(make_config(fake, langsmith_project="secagent"), tmp_path)
    assert len(calls) == 1


def test_wrapped_client_still_calls_the_model(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    fake.responses.append({"content": "ok"})
    gw = LlmGateway(make_config(fake, langsmith_project="secagent"), tmp_path)
    response = gw.complete("investigate", [{"role": "user", "content": "x"}], prompt_version="p_v1", budget=Budget(),
                           case_id="c1")
    assert response.content == "ok" and "langsmith_extra" not in json.dumps(fake.requests[0])


def _spy_context(monkeypatch):
    seen = []

    @contextlib.contextmanager
    def spy(**kwargs):
        seen.append(kwargs)
        yield

    monkeypatch.setattr(orchestrator, "tracing_context", spy)
    return seen


def test_scan_disables_tracing_without_project(fake, tmp_path, monkeypatch):
    seen = _spy_context(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    orchestrator.run_scan(FIX / "vulnerable", design=[], out=tmp_path, config=make_config(fake),
                          slices_file=FIX / "slices.yml")
    assert seen[0]["enabled"] is False and seen[0]["client"] is None


def test_scan_traces_into_the_configured_project(fake, tmp_path, monkeypatch):
    seen = _spy_context(monkeypatch)
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    orchestrator.run_scan(FIX / "vulnerable", design=[], out=tmp_path,
                          config=make_config(fake, langsmith_project="secagent"), slices_file=FIX / "slices.yml")
    assert seen[0]["enabled"] is True and seen[0]["project_name"] == "secagent"
    assert isinstance(seen[0]["client"], Client)  # 단계 기록을 줄이는 클라이언트로 보낸다
