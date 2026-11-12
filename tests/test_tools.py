import json
from pathlib import Path

import pytest
from conftest import make_config

from taki.adapters.lang.java_index import build_index
from taki.adapters.lang.mybatis import parse_mappers
from taki.adapters.lang.spring import extract_spring
from taki.core.orchestrator import run_scan
from taki.llm.gateway import LlmGateway
from taki.llm.roles import investigate, review
from taki.schemas.models import Budget, Case, CaseSource, Claim, EvidencePath, ReviewResult
from taki.steps.cases import load_rules
from taki.steps.scope import scan_scope
from taki.tools.readonly import ReadOnlyTools

FIX = Path(__file__).parent / "fixtures" / "spring-members"
VULN = FIX / "vulnerable"
CONTROLLER = "src/main/java/demo/member/MemberController.java"
CASE = Case(
    case_id="c1", source=CaseSource.rule, subject_id="R1", question="q", slice_id="s", budget=Budget(max_tool_calls=8)
)


@pytest.fixture(scope="module")
def tools():
    snapshot = scan_scope(VULN)
    index = build_index(snapshot)
    return ReadOnlyTools(
        snapshot, index, parse_mappers(snapshot), extract_spring(snapshot, index).entrypoints, [FIX / "design.md"]
    )


@pytest.fixture
def gw(fake, tmp_path):
    return LlmGateway(make_config(fake), tmp_path)


def _tool(name, **arguments):
    return {"tool_calls": [{"name": name, "arguments": arguments}]}


def test_read_code_shows_line_numbers(tools):
    text = tools.call("read_code", {"path": CONTROLLER, "start": 35, "end": 35})
    assert text == "   35|     public void delete(@PathVariable long id) {"


def test_search_finds_text_case_insensitively(tools):
    assert f"{CONTROLLER}:35" in tools.call("search", {"pattern": "VOID DELETE"})


def test_search_treats_pattern_as_plain_text(tools):
    assert "없음" in tools.call("search", {"pattern": "(a+)+$"})


def test_callers_and_callees(tools):
    assert "MemberController.delete" in tools.call("callers", {"symbol": "MemberService.delete"})
    assert "MemberService.delete" in tools.call("callees", {"symbol": "MemberController.delete"})


def test_field_usages_lists_positions(tools):
    assert "MemberMapper.xml" in tools.call("field_usages", {"name": "status"})


def test_route_info_reports_guards(tools):
    info = json.loads(tools.call("route_info", {"method": "DELETE", "path": "/api/v1/admin/members/{id}"}))
    assert info["effective_guards"] == ["authenticated"] and info["middleware_complete"] is True


def test_read_doc_section(tools):
    assert "관리자 권한" in tools.call("read_doc", {"doc": "design.md", "section": "회원 관리 API"})


def test_read_doc_outside_list_is_error(tools):
    assert tools.call("read_doc", {"doc": "../../secret.md", "section": "x"}).startswith("오류")


def test_tool_loop_then_submit(fake, gw, tools):
    claim = {"claim": "absent", "statement": "s"}
    fake.responses += [_tool("read_code", path=CONTROLLER, start=1, end=2), _tool("submit_result", claims=[claim])]
    result = investigate(CASE, "code", gateway=gw, tools=tools)
    assert result.claims[0].claim == Claim.absent and len(fake.requests) == 2
    tool_message = fake.requests[1]["messages"][-1]
    assert tool_message["role"] == "tool" and "package demo.member" in tool_message["content"]
    assert {t["function"]["name"] for t in fake.requests[0]["tools"]} >= {"read_code", "submit_result"}


def test_plain_json_answer_also_ends_loop(fake, gw, tools):
    fake.responses.append({"content": '{"claims": []}'})
    assert investigate(CASE, "code", gateway=gw, tools=tools).claims == []


def test_bad_submit_is_sent_back(fake, gw, tools):
    fake.responses += [_tool("submit_result", claims=[{"claim": "모름"}]), _tool("submit_result", claims=[])]
    assert investigate(CASE, "code", gateway=gw, tools=tools).claims == []
    assert fake.requests[1]["messages"][-1]["content"].startswith("오류")


def test_limit_asks_final_answer_with_readings(fake, gw, tools):
    limit = CASE.budget.max_tool_calls
    final = {"claims": [{"claim": "absent", "statement": "읽은 내용으로 판정"}]}
    fake.responses += [_tool("search", pattern="delete") for _ in range(limit + 1)] + [{"content": json.dumps(final)}]
    result = investigate(CASE, "code", gateway=gw, tools=tools)
    last = fake.requests[-1]
    assert len(fake.requests) == limit + 2 and "tools" not in last
    assert "<<<DATA TOOL_RESULTS>>>" in json.dumps(last, ensure_ascii=False)
    assert result.claims[0].statement == "읽은 내용으로 판정"


def test_bad_submit_counts_toward_limit(fake, gw, tools):
    limit = CASE.budget.max_tool_calls
    bad = _tool("submit_result", claims=[{"claim": "모름"}])
    fake.responses += [bad for _ in range(limit + 1)] + [{"content": '{"claims": []}'}]
    assert investigate(CASE, "code", gateway=gw, tools=tools).claims == []
    assert len(fake.requests) == limit + 2 and "tools" not in fake.requests[-1]


def test_high_tool_limit_does_not_hit_recursion_limit(fake, gw, tools):
    case = CASE.model_copy(update={"budget": Budget(max_tool_calls=30)})
    fake.responses += [_tool("search", pattern="x") for _ in range(30)] + [_tool("submit_result", claims=[])]
    assert investigate(case, "code", gateway=gw, tools=tools).claims == [] and len(fake.requests) == 31


def test_path_traversal_returns_error_text(tools):
    assert tools.call("read_code", {"path": "../../../etc/passwd", "start": 1, "end": 1}).startswith("오류")


def test_forbidden_dir_not_readable(tmp_path):
    (tmp_path / "a.java").write_text("class A {}\n")
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "answer.java").write_text("secret\n")
    tools = ReadOnlyTools(scan_scope(tmp_path))
    assert tools.call("read_code", {"path": "work/answer.java", "start": 1, "end": 1}).startswith("오류")
    assert "answer" not in tools.call("search", {"pattern": "secret"})


def test_unknown_tool_returns_error_text(tools):
    assert tools.call("rm_rf", {}).startswith("오류") and tools.call("read_code", {}).startswith("오류")


def test_tool_result_goes_through_masking(fake, gw, tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.java").write_text('class A { String k = "sk-abc123def456ghi789"; }\n')
    tools = ReadOnlyTools(scan_scope(tmp_path / "t"))
    fake.responses += [_tool("read_code", path="a.java", start=1, end=1), _tool("submit_result", claims=[])]
    investigate(CASE, "code", gateway=gw, tools=tools)
    assert "sk-abc" not in json.dumps(fake.requests[1])


def test_tool_calls_recorded(fake, gw, tools, tmp_path):
    fake.responses += [_tool("search", pattern="x"), _tool("submit_result", claims=[])]
    investigate(CASE, "code", gateway=gw, tools=tools)
    rows = [json.loads(x) for x in (tmp_path / "manifest.jsonl").read_text().splitlines()]
    assert rows[0]["tool_calls"] == ["search"] and rows[1]["tool_calls"] == ["submit_result"]


def test_review_can_read_upper_guard(fake, gw, tools):
    evidence = EvidencePath(claim=Claim.absent, statement="s")
    proof = {"claim": "implemented", "statement": "상위에 있다"}
    fake.responses += [
        _tool("read_code", path="src/main/java/demo/config/SecurityConfig.java", start=1, end=20),
        _tool("submit_result", result="refuted", reason="r", evidence=proof),
    ]
    out = review(evidence, "code", gateway=gw, tools=tools)
    assert out.result == ReviewResult.refuted and out.evidence.claim == Claim.implemented
    assert "SecurityFilterChain" in fake.requests[1]["messages"][-1]["content"]


def test_scan_gives_tools_to_investigator(fake, tmp_path):
    fake.responses.extend(json.loads((FIX / "fake_script.json").read_text(encoding="utf-8")))
    run_scan(
        VULN, design=[FIX / "design.md"], out=tmp_path, config=make_config(fake), rules=load_rules(FIX / "rules.yml")
    )
    assert "tools" in fake.requests[0] and "tools" not in fake.requests[-1]  # 수정 제안은 도구를 쓰지 않는다


def test_tool_reasoning_split_keeps_reasoning_for_final_answer(fake, tmp_path, tools):
    config = make_config(fake, reasoning_effort="medium", tool_reasoning_effort="none")
    gateway = LlmGateway(config, tmp_path)
    fake.responses += [
        _tool("read_code", path=CONTROLLER, start=35, end=35),
        _tool("submit_result", claims=[]),
        {"content": json.dumps({"claims": [{"claim": "absent", "statement": "최종"}]})},
    ]
    result = investigate(CASE, "code", gateway=gateway, tools=tools)
    first, second, final = fake.requests
    assert first["reasoning_effort"] == "none" and "tools" in first and second["reasoning_effort"] == "none"
    assert final["reasoning_effort"] == "medium" and "tools" not in final
    assert "public void delete" in json.dumps(final["messages"], ensure_ascii=False)
    assert all(m["role"] in ("system", "user") for m in final["messages"])
    assert result.claims[0].statement == "최종"


def test_without_split_first_submit_is_final(fake, gw, tools):
    fake.responses += [_tool("submit_result", claims=[])]
    investigate(CASE, "code", gateway=gw, tools=tools)
    assert len(fake.requests) == 1


def test_config_secret_is_masked_in_tools_and_slices(tmp_path):
    from taki.schemas.models import Slice, SliceFile
    from taki.steps.slices import render_slice

    (tmp_path / "application.properties").write_text("spring.datasource.password=tiger123\n")
    snapshot = scan_scope(tmp_path)
    assert "tiger123" not in ReadOnlyTools(snapshot).call(
        "read_code", {"path": "application.properties", "start": 1, "end": 1}
    )
    assert "tiger123" not in ReadOnlyTools(snapshot).call("search", {"pattern": "datasource"})
    one = Slice(slice_id="s", name="s", files=[SliceFile(path="application.properties")])
    assert "tiger123" not in render_slice(one, snapshot)


def test_bad_argument_types_return_error_text(tools):
    assert tools.call("read_code", {"path": CONTROLLER, "start": "line 3", "end": 4}).startswith("오류")
