"""LangSmith로 나가는 기록의 경계. LLM 호출 기록만 그대로 두고, 그래프 단계 기록에는 코드 원문이 없어야 한다."""

import json
from pathlib import Path

import pytest
from conftest import make_config
from langsmith import Client, tracing_context

from agent.adapters.lang.java_index import build_index
from agent.adapters.lang.mybatis import parse_mappers
from agent.core import tracing
from agent.core.orchestrator import run_scan
from agent.llm.gateway import LlmGateway
from agent.llm.roles import investigate
from agent.schemas.models import Budget, Case, CaseSource
from agent.steps.scope import scan_scope
from agent.tools.readonly import ReadOnlyTools

FIX = Path(__file__).parent / "fixtures" / "spring-members"
MARK = "MARKER_ZQX_CODE"
CASE = Case(case_id="c1", source=CaseSource.rule, subject_id="R1", question="q", slice_id="s", budget=Budget())


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


@pytest.fixture
def recorded(monkeypatch):
    """가리기 함수를 지난 (원본, 결과)와 전송 직전 호출을 모은다. 실제로 보내지는 않는다."""
    seen, posts = [], []
    original = tracing.hide_payload

    def record(data):
        result = original(data)
        seen.append((data, result))
        return result

    monkeypatch.setattr(tracing, "hide_payload", record)
    monkeypatch.setattr(Client, "_create_run", lambda self, *a, **k: posts.append(a))
    monkeypatch.setattr(Client, "_update_run", lambda self, *a, **k: posts.append(a))
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    monkeypatch.setenv("LANGSMITH_ENDPOINT", "http://127.0.0.1:9")
    return seen, posts


def test_hide_payload_keeps_llm_and_drops_code():
    llm_in = {"model": "m", "messages": [{"role": "user", "content": MARK}]}
    llm_out = {"choices": [{"message": {"content": MARK}}]}
    assert tracing.hide_payload(llm_in) is llm_in and tracing.hide_payload(llm_out) is llm_out
    state = {"history": [{"content": MARK}], "case": CASE, "used": 3, "done": False, "error": "e",
             "slice_text": MARK, "path": Path("/a/B.java"), "gateway": object()}
    brief = tracing.hide_payload(state)
    assert MARK not in _dump(brief) and state["slice_text"] == MARK  # 원본 상태는 건드리지 않는다
    assert brief["used"] == 3 and brief["done"] is False and brief["case"] == "c1" and brief["error"] == "e"
    assert brief["history"] == "1개" and brief["path"] == "B.java" and brief["gateway"] == "<object>"


def test_graph_runs_keep_code_out(fake, tmp_path, recorded):
    seen, _ = recorded
    root = tmp_path / "t"
    (root / "src").mkdir(parents=True)
    (root / "src" / "A.java").write_text(f'class A {{ String s = "{MARK}"; }}\n')
    snapshot = scan_scope(root)
    tools = ReadOnlyTools(snapshot, build_index(snapshot), parse_mappers(snapshot), [], [])
    gateway = LlmGateway(make_config(fake, langsmith_project="t"), tmp_path / "o")
    fake.responses += [{"tool_calls": [{"name": "read_code", "arguments": {"path": "src/A.java", "start": 1, "end": 1}}]},
                       {"tool_calls": [{"name": "submit_result", "arguments": {"claims": []}}]}]
    with tracing_context(enabled=True, project_name="t", client=tracing.trace_client()):
        investigate(CASE, f"code {MARK}", gateway=gateway, tools=tools)
    assert any("history" in data for data, _ in seen)  # 도구 반복 그래프의 단계 기록이 이 클라이언트로 갔다
    assert all(MARK not in _dump(result) for data, result in seen if not tracing.is_llm_payload(data))
    assert any(MARK in _dump(result) for data, result in seen if tracing.is_llm_payload(data))


def test_env_tracing_alone_sends_nothing(fake, tmp_path, recorded, monkeypatch):
    seen, posts = recorded
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": []}'})
    run_scan(FIX / "vulnerable", design=[], out=tmp_path, config=make_config(fake), slices_file=FIX / "slices.yml")
    assert seen == [] and posts == []
