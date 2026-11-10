import csv
import json
from pathlib import Path

import pytest
from conftest import make_config

from agent.schemas.models import Budget, Slice
from agent.steps.cases import build_cases
from agent.steps.lenses import load_lenses
from agent.steps.scope import scan_scope
from agent.steps.slices import load_slices
from eval.run import run_condition
from eval.score import BENCH, score

CONDITIONS = {"B": {"extensions": [".java", ".html"], "server_exclude": ["frontend/"], "max_input_tokens": 100000}}
CLAIM = {"claim": "absent", "statement": "s", "cwe": "CWE-862", "category": 2, "root_symbol": "A.b",
         "hops": [{"file": "A.java", "start": 1, "end": 1, "quote": "class A {}", "role": "root_control"}]}
DEV_SLICES = Path(__file__).resolve().parents[1] / "eval" / "slices" / "dev.yml"
needs_bench = pytest.mark.skipif(not BENCH.exists(), reason="벤치마크 폴더가 없음")


@pytest.fixture
def target(tmp_path):
    root = tmp_path / "t"
    (root / "frontend").mkdir(parents=True)
    (root / "A.java").write_text("class A {}\n")
    (root / "frontend" / "b.html").write_text("<div>" + "x" * 300 + "</div>\n")
    (root / "slices.yml").write_text("- name: a\n  files: [{path: A.java}]\n  flows: [{method: GET, path: /a}]\n"
                                     "- name: b\n  files: [{path: A.java}]\n")
    return root


def test_lenses_has_11_questions_in_8_categories():
    lenses = load_lenses()
    assert len(lenses) == 11 and len({x.lens_id for x in lenses}) == 11 and {x.category for x in lenses} == set(range(1, 9))


def test_one_question_case_per_slice():
    slices = [Slice(slice_id="a", name="a"), Slice(slice_id="b", name="b")]
    cases = build_cases(slices, [], Budget(), lenses=load_lenses())
    assert [c.slice_id for c in cases] == ["a", "b"] and cases[0].case_id != cases[1].case_id
    assert all(x.lens_id in cases[0].question for x in load_lenses())


def test_flows_without_guards_have_no_table(target):
    assert load_slices(target / "slices.yml", scan_scope(target))[0].sibling_table == []


def test_condition_c_calls_once_per_slice(fake, target, tmp_path):
    fake.responses += [{"content": json.dumps({"claims": [CLAIM]})}, {"content": '{"claims": []}'}]
    record = run_condition("C", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=1,
                           slices_file=target / "slices.yml")
    assert len(fake.requests) == 2 and record["status"] == "ok" and record["claims"] == 1
    results = json.loads((tmp_path / "o" / "r1.sarif").read_text())["runs"][0]["results"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "A.java"
    saved = json.loads((tmp_path / "o" / "r1.run.json").read_text())
    assert saved["input_tokens"] == 20 and saved["calls"] == 2


def test_condition_c_failed_slice_is_not_zero_findings(fake, target, tmp_path):
    fake.responses += [{"content": '{"claims": []}'}]  # 두 번째 묶음은 500
    record = run_condition("C", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=1,
                           slices_file=target / "slices.yml")
    assert record["status"] == "partial" and record["errors"]


def test_condition_b_sends_everything_in_one_call(fake, target, tmp_path):
    fake.responses.append({"content": '{"claims": []}'})
    record = run_condition("B", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=2)
    assert len(fake.requests) == 1 and record["status"] == "ok" and (tmp_path / "o" / "r2.sarif").exists()
    assert "b.html" in str(fake.requests[0]["messages"][1]["content"])


def test_b_too_large_is_recorded(fake, target, tmp_path):
    fake.responses.append({"content": '{"claims": []}'})
    limited = {"B": {**CONDITIONS["B"], "max_input_tokens": 1500}}
    config = make_config(fake)
    record = run_condition("B", target, tmp_path / "o", config=config, conditions=limited, repeat=1)
    assert record["status"] == "ok"  # 전체가 한도 안이면 그대로 보낸다

    too_small = {"B": {**CONDITIONS["B"], "max_input_tokens": 1}}
    fake.requests.clear()
    record = run_condition("B", target, tmp_path / "p", config=config, conditions=too_small, repeat=1)
    assert record["status"] == "TOO_LARGE" and fake.requests == [] and not (tmp_path / "p" / "r1.sarif").exists()
    assert json.loads((tmp_path / "p" / "r1.run.json").read_text())["status"] == "TOO_LARGE"


def test_b_falls_back_to_server_code_and_says_so(fake, target, tmp_path, monkeypatch):
    fake.responses.append({"content": '{"claims": []}'})
    # 프롬프트 길이에 맞춰 전체는 넘고 서버 코드만은 들어가는 한도를 찾는다.
    from agent.llm.roles import PROMPT_DIR

    prompt = (PROMPT_DIR / "investigate_v1.md").read_text(encoding="utf-8")
    questions = sum(len(x.question) + 20 for x in load_lenses())
    limit = (len(prompt) + questions + 400) // 3
    limited = {"B": {**CONDITIONS["B"], "max_input_tokens": limit}}
    record = run_condition("B", target, tmp_path / "o", config=make_config(fake), conditions=limited, repeat=1)
    assert record["status"] == "TOO_LARGE" and record["input"] == "server_only" and len(fake.requests) == 1
    assert "b.html" not in str(fake.requests[0]["messages"][1]["content"])


@needs_bench
def test_sarif_shape_is_scored(tmp_path):
    runs = tmp_path / "runs" / "DEV-D0"
    runs.mkdir(parents=True)
    for name in ("r1", "r2"):
        (runs / f"{name}.sarif").write_text(json.dumps(
            {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": name}}, "results": []}]}))
        (runs / f"{name}.run.json").write_text("{}")
    score(tmp_path / "runs", tmp_path / "out")
    rows = list(csv.DictReader((tmp_path / "out" / "summary.csv").open()))
    assert {r["tool"] for r in rows} == {"r1", "r2", "UNION"}
    stability = list(csv.DictReader((tmp_path / "out" / "stability.csv").open()))
    assert stability and stability[0]["runs"] == "2" and stability[0]["flagged_runs"] == "0"


@needs_bench
@pytest.mark.parametrize("variant", ["DEV-D0", "DEV-D1", "DEV-D2"])
def test_dev_slices_fit_every_variant(variant):
    snapshot = scan_scope(BENCH / "artifacts" / variant / "scan-input")
    slices = load_slices(DEV_SLICES, snapshot)
    assert [s.name for s in slices] == ["reviews", "products", "registration"]
    assert [s.truncated for s in slices] == [[], [], []]
    assert all(s.flows and all(f.middleware_complete for f in s.flows) for s in slices)
