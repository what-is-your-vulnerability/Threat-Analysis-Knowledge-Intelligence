import threading

from conftest import make_config

from agent.adapters.scanner.docker import ScannerSpec
from agent.adapters.scanner.sarif import ScanOutcome
from agent.core import orchestrator
from agent.core.orchestrator import run_scan
from agent.schemas.models import Capability, Fact, LedgerState

NO_ISSUE = {"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'}


def _spec(name):
    return ScannerSpec(name=name, image="i", command=["x", "{sarif}"])


def _target(tmp_path, files=("app.mjs",)):
    root = tmp_path / "t"
    root.mkdir()
    for name in files:
        (root / name).write_text("export const a = 1;\n")
    return root


def _alert(name):
    return Fact(kind="alert", file="app.mjs", line=1, tool=name, detail={"cwe": "CWE-918", "rule": "r", "message": f"{name} 경고"})


def test_scan_is_a_langgraph_graph():
    nodes = set(orchestrator.SCAN_GRAPH.get_graph().nodes)
    assert {"prepare", "scanner", "structure", "plan_cases", "run_one_case", "findings", "report"} <= nodes


def test_scanners_run_in_parallel(fake, tmp_path, monkeypatch):
    both_running = threading.Barrier(2, timeout=5)  # 차례로 돌면 첫 도구가 5초 뒤 BrokenBarrierError로 멈춘다

    def scan(spec, snapshot, out):
        both_running.wait()
        return ScanOutcome(Capability.supported, alerts=[_alert(spec.name)])

    monkeypatch.setattr(orchestrator, "run_scanner", scan)
    fake.responses.append(NO_ISSUE)
    r = run_scan(_target(tmp_path), design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_spec("a"), _spec("b")]))
    assert {f.statement for f in r.findings} == {"a 경고", "b 경고"}


def test_one_scanner_fails_other_results_kept(fake, tmp_path, monkeypatch):
    def scan(spec, snapshot, out):
        if spec.name == "a":
            return ScanOutcome(Capability.failed, errors=["이미지 없음"])
        return ScanOutcome(Capability.supported, alerts=[_alert("b")])

    monkeypatch.setattr(orchestrator, "run_scanner", scan)
    fake.responses.append(NO_ISSUE)
    r = run_scan(_target(tmp_path), design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_spec("a"), _spec("b")]))
    assert [f.statement for f in r.findings if f.tool_confirmed] == ["b 경고"] and r.exit_code == 1
    assert any(c.subject == "scanner:a" and c.state == LedgerState.not_seen and "이미지 없음" in c.reason for c in r.ledger)


def test_scanners_run_before_llm(fake, tmp_path, monkeypatch):
    seen_requests = []

    def scan(spec, snapshot, out):
        seen_requests.append(len(fake.requests))
        return ScanOutcome(Capability.supported)

    monkeypatch.setattr(orchestrator, "run_scanner", scan)
    fake.responses.append(NO_ISSUE)
    run_scan(_target(tmp_path), design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_spec("a")]))
    assert seen_requests == [0] and fake.requests


def test_many_cases_do_not_hit_recursion_limit(fake, tmp_path):
    root = _target(tmp_path, files=[f"m{n}.mjs" for n in range(30)])
    slices = tmp_path / "slices.yml"
    slices.write_text("".join(f"- name: s{n}\n  files:\n    - path: m{n}.mjs\n" for n in range(30)))
    fake.responses.append(NO_ISSUE)
    r = run_scan(root, design=[], out=tmp_path / "o", config=make_config(fake), slices_file=slices)
    assert len(r.cases) == 30 and len(fake.requests) == 30
    assert sum(1 for c in r.ledger if c.subject.startswith("L")) == 330


def test_scope_failure_skips_to_report(fake, tmp_path, monkeypatch):
    def scan(*a, **k):
        raise AssertionError("범위 확인에 실패하면 스캐너를 돌리지 않는다")

    monkeypatch.setattr(orchestrator, "run_scanner", scan)
    (tmp_path / "empty").mkdir()
    r = run_scan(tmp_path / "empty", design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_spec("a")]))
    assert r.exit_code == 3 and r.error == "분석할 파일이 없습니다." and (tmp_path / "o" / "report.json").exists()
    assert fake.requests == []


def test_scanner_exception_is_not_seen_not_a_crash(fake, tmp_path, monkeypatch):
    def scan(spec, snapshot, out):
        if spec.name == "a":
            raise KeyError("runs")
        return ScanOutcome(Capability.supported, alerts=[_alert("b")])

    monkeypatch.setattr(orchestrator, "run_scanner", scan)
    fake.responses.append(NO_ISSUE)
    r = run_scan(_target(tmp_path), design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_spec("a"), _spec("b")]))
    assert (tmp_path / "o" / "report.json").exists() and r.exit_code == 1
    assert [f.statement for f in r.findings if f.tool_confirmed] == ["b 경고"]
    assert any(c.subject == "scanner:a" and c.state == LedgerState.not_seen and "KeyError" in c.reason for c in r.ledger)
