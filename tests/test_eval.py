import csv
import json
from pathlib import Path

import pytest
from conftest import make_config

from eval.run import run_condition
from eval.score import BENCH, score
from taki.schemas.models import Budget, Slice
from taki.steps.cases import build_cases
from taki.steps.lenses import load_lenses
from taki.steps.scope import scan_scope
from taki.steps.slices import load_slices

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
    from taki.llm.roles import PROMPT_DIR

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


RULES_YML = """- rule_id: R1
  title: 수정은 소유자만
  requirement_quote: 사용자는 자신이 작성한 리뷰만 수정할 수 있다.
  doc_ref: reviews.md#7
  category: 2
  cwe: CWE-639
  applies_to: ["GET /a"]
  status: approved
- rule_id: R2
  title: 승인 안 됨
  requirement_quote: 무시
  applies_to: ["GET /a"]
  status: pending
"""
ABSENT = {"claim": "absent", "statement": "s", "cwe": "CWE-862", "category": 2, "root_symbol": "A.b",
          "expected_positions": ["A.b"], "basis": ["x"],
          "hops": [{"file": "A.java", "start": 1, "end": 1, "quote": "class A {}", "role": "root_control"}]}
INVENTED = {**ABSENT, "statement": "지어낸 인용", "root_symbol": "A.c",
            "hops": [{"file": "A.java", "start": 1, "end": 1, "quote": "없는 코드", "role": "root_control"}]}


def _rules_file(target):
    path = target / "rules.yml"
    path.write_text(RULES_YML, encoding="utf-8")
    return path


def test_condition_d_uses_rules_from_design_only(fake, target, tmp_path):
    fake.responses += [{"match": "lens_id별로", "content": '{"claims": []}'},
                       {"content": json.dumps({"claims": [CLAIM]})}]
    slices = target / "s.yml"
    slices.write_text("- name: a\n  files: [{path: A.java}]\n  flows: [{method: GET, path: /a}]\n")
    record = run_condition("D", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=1,
                           slices_file=slices, rules_file=_rules_file(target))
    sent = [json.dumps(r["messages"], ensure_ascii=False) for r in fake.requests]
    assert record["status"] == "ok" and len(sent) == 2 and record["claims"] == 1
    assert any("사용자는 자신이 작성한 리뷰만 수정할 수 있다." in t for t in sent)
    assert not any("승인 안 됨" in t for t in sent)
    assert not any("ground-truth" in t for t in sent)
    assert (tmp_path / "o" / "r1.sarif").exists()


def test_condition_e_applies_evidence_and_review(fake, target, tmp_path):
    fake.responses += [
        {"match": "재검토한다", "content": '{"result": "kept", "reason": "없다"}'},
        {"match": "수정 방법을 제안한다", "content": '{"location": "l", "code_example": "c", "check_scenario": "s"}'},
        {"match": "lens_id별로", "content": '{"claims": []}'},
        {"match": "조사 항목 하나를", "content": json.dumps({"claims": [ABSENT, INVENTED]})},
    ]
    slices = target / "s.yml"
    slices.write_text("- name: a\n  files: [{path: A.java}]\n  flows: [{method: GET, path: /a, middleware_complete: true}]\n")
    record = run_condition("E", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=1,
                           slices_file=slices, rules_file=_rules_file(target), design=[])
    results = json.loads((tmp_path / "o" / "r1.sarif").read_text())["runs"][0]["results"]
    assert [r["message"]["text"] for r in results] == ["s"] and record["verdicts"]["missing_suspected"] == 1
    assert record["verdicts"]["unverified"] == 1 and record["calls"] >= 3


def test_condition_e_failure_is_not_zero_findings(fake, target, tmp_path):
    slices = target / "s.yml"
    slices.write_text("- name: a\n  files: [{path: A.java}]\n  flows: [{method: GET, path: /a, middleware_complete: true}]\n")
    record = run_condition("E", target, tmp_path / "o", config=make_config(fake), conditions=CONDITIONS, repeat=1,
                           slices_file=slices, rules_file=_rules_file(target), design=[])
    assert record["status"] == "failed" and not (tmp_path / "o" / "r1.sarif").exists()


@needs_bench
def test_dev_rules_match_dev_flows():
    from taki.steps.cases import load_rules

    rules_file = Path(__file__).resolve().parents[1] / "eval" / "rules" / "dev.yml"
    if not rules_file.exists():
        pytest.skip("eval/rules/dev.yml을 아직 만들지 않음")
    snapshot = scan_scope(BENCH / "artifacts" / "DEV-D0" / "scan-input")
    rules = load_rules(rules_file)
    cases = build_cases(load_slices(DEV_SLICES, snapshot), rules, Budget())
    assert rules and {r.rule_id for r in rules} == {c.subject_id for c in cases}
