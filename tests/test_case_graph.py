import json
from pathlib import Path

from conftest import make_config

from taki.adapters.lang.java_index import build_index
from taki.adapters.lang.mybatis import parse_mappers
from taki.adapters.lang.spring import extract_spring
from taki.core.case_graph import ScanRuntime, run_case
from taki.llm.gateway import LlmGateway
from taki.schemas.models import Budget, CaseSource, LedgerState, VerdictState
from taki.steps.cases import build_cases, load_rules
from taki.steps.lenses import load_lenses
from taki.steps.scope import scan_scope
from taki.steps.slices import load_slices, locate_handlers
from taki.tools.readonly import ReadOnlyTools

FIX = Path(__file__).parent / "fixtures" / "spring-members"
BAD_QUOTE = {"claims": [{"claim": "absent", "statement": "s", "root_symbol": "MemberController.delete", "basis": ["x"],
                         "expected_positions": ["y"],
                         "hops": [{"file": "src/main/java/demo/member/MemberController.java", "start": 1, "end": 1,
                                   "quote": "없는 문장", "role": "root_control"}]}]}


def _setup(fake, tmp_path):
    snapshot = scan_scope(FIX / "vulnerable")
    index = build_index(snapshot)
    mappers = parse_mappers(snapshot)
    spring = extract_spring(snapshot, index)
    slices = load_slices(FIX / "slices.yml", snapshot)
    locate_handlers(slices, index)
    lenses = load_lenses()
    runtime = ScanRuntime(gateway=LlmGateway(make_config(fake), tmp_path),
                          reader=ReadOnlyTools(snapshot, index, mappers, spring.entrypoints, []),
                          index=index, mappers=mappers, spring=spring, lenses=lenses)
    cases = build_cases(slices, load_rules(FIX / "rules.yml"), Budget(), lenses=lenses)
    return snapshot, runtime, {s.slice_id: s for s in slices}, cases


def _case(cases, source):
    return next(c for c in cases if c.source == source)


def test_quote_retry_goes_back_once(fake, tmp_path):
    snapshot, runtime, slices, cases = _setup(fake, tmp_path)
    case = _case(cases, CaseSource.rule)
    fake.responses += [{"content": json.dumps(BAD_QUOTE)}, {"content": json.dumps(BAD_QUOTE)}]
    verdicts, ledger = run_case(case, slices[case.slice_id], load_rules(FIX / "rules.yml")[0], snapshot, runtime)
    assert len(fake.requests) == 2 and "quote_not_found" in json.dumps(fake.requests[1]["messages"], ensure_ascii=False)
    assert [v.state for v in verdicts] == [VerdictState.unverified] and verdicts[0].manifest_ids
    assert ledger[0].state == LedgerState.checked


def test_llm_error_ends_in_fail_node(fake, tmp_path):
    snapshot, runtime, slices, cases = _setup(fake, tmp_path)
    case = _case(cases, CaseSource.rule)
    verdicts, ledger = run_case(case, slices[case.slice_id], None, snapshot, runtime)  # 모의 LLM이 500을 돌려준다
    assert len(verdicts) == 1 and verdicts[0].state == VerdictState.unverified and verdicts[0].evidence is None
    assert ledger[0].state == LedgerState.not_seen and ledger[0].reason


def test_question_case_without_claims_makes_no_verdict(fake, tmp_path):
    snapshot, runtime, slices, cases = _setup(fake, tmp_path)
    case = _case(cases, CaseSource.question)
    fake.responses.append({"content": json.dumps({"claims": [], "dispositions": [
        {"lens_id": "L1", "disposition": "no_issue"}]})})
    verdicts, ledger = run_case(case, slices[case.slice_id], None, snapshot, runtime)
    assert verdicts == [] and len(ledger) == 11 and ledger[0].state == LedgerState.checked


def test_alerts_reach_investigation_text(fake, tmp_path):
    from taki.schemas.models import Fact

    snapshot, runtime, slices, cases = _setup(fake, tmp_path)
    case = _case(cases, CaseSource.rule)
    alert = Fact(kind="alert", file="src/main/java/demo/member/MemberService.java", line=22, tool="semgrep",
                 detail={"cwe": "CWE-89", "rule": "sql", "message": "SQL 조립 경고 원문"})
    fake.responses.append({"content": '{"claims": []}'})
    run_case(case, slices[case.slice_id], None, snapshot, runtime, alerts=[alert])
    assert "SQL 조립 경고 원문" in json.dumps(fake.requests[0]["messages"], ensure_ascii=False)
