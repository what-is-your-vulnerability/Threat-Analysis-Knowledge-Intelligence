import subprocess
from pathlib import Path

import pytest

from agent.adapters.scanner.docker import (
    ScannerSpec,
    docker_args,
    keep_snapshot_alerts,
    load_scanner,
    plan_scanners,
    run_scanner,
)
from agent.adapters.scanner.sarif import ScanOutcome
from agent.config import RULES_DIR, AgentConfig, ConfigError, load_config
from agent.core.orchestrator import run_scan
from agent.schemas.models import Capability, Fact, LedgerState
from agent.steps.scope import scan_scope

FIX = Path(__file__).parent / "fixtures" / "semgrep"


def _snapshot():
    return scan_scope(FIX / "app")


def _semgrep():
    return load_scanner("semgrep", Path.cwd())


def _alert(file, cwe="CWE-89"):
    return Fact(kind="alert", file=file, line=1, tool="semgrep", detail={"cwe": cwe, "rule": "r", "message": "m"})


def test_builtin_semgrep_definition_loads():
    spec = _semgrep()
    assert spec.image == "semgrep/semgrep:1.183.0" and spec.rules == [RULES_DIR / "semgrep" / "java-sql.yml"]


def test_docker_args_isolate_and_expand(tmp_path):
    args = docker_args(_semgrep(), _snapshot(), tmp_path, "secagent-semgrep-x")
    assert args[:2] == ["docker", "run"] and "--rm" in args and "--read-only" in args
    assert args[args.index("--network") + 1] == "none" and args[args.index("--pull") + 1] == "missing"
    assert f"type=bind,src={FIX / 'app'},dst=/src,readonly" in args and "/out/semgrep.sarif" in args
    assert args[args.index("--config") + 1] == "/rules/0.yml" and "{rules}" not in args and "-v" not in args
    assert "semgrep/semgrep:1.183.0" in args and "--metrics=off" in args


def test_mount_path_with_comma_is_quoted(tmp_path):
    root = tmp_path / "a,b"
    root.mkdir()
    (root / "A.java").write_text("class A {}\n")
    args = docker_args(_semgrep(), scan_scope(root), tmp_path, "n")
    assert f'"src={root}",dst=/src,readonly' in " ".join(args)


def test_bad_scanner_yaml_stops_before_scan(tmp_path):
    for bad in ({"name": "a/b", "image": "i", "command": ["x", "{sarif}"]},
                {"name": "a", "image": "i", "command": ["x"]},
                {"name": "a", "image": "i", "command": ["x", "{sarif}", "{oops}"]},
                {"name": "a", "image": "i", "command": ["x", "--out={sarif}", "--config={rules}"]},
                {"name": "a", "image": "i", "command": ["x", "{sarif}"], "rules": ["nope/*.yml"]},
                {"name": "a", "image": "i", "command": ["x", "{sarif}"], "imgae": "typo"},
                "no-such-scanner", "../semgrep"):
        with pytest.raises(ConfigError):
            load_scanner(bad, tmp_path)


def test_inline_definition_rules_are_relative_to_base(tmp_path):
    (tmp_path / "r.yml").write_text("rules: []\n")
    spec = load_scanner({"name": "mine", "image": "i", "command": ["x", "{sarif}", "{rules}"], "rules": ["*.yml"]}, tmp_path)
    assert spec.rules == [(tmp_path / "r.yml").resolve()]


def test_config_loads_scanner_names(tmp_path):
    (tmp_path / "agent.yml").write_text("scanners: [semgrep]\n")
    assert [s.name for s in load_config(tmp_path / "agent.yml").scanners] == ["semgrep"]


def test_bad_scanner_in_config_is_config_error(tmp_path):
    (tmp_path / "agent.yml").write_text("scanners: [no-such-scanner]\n")
    with pytest.raises(ConfigError, match="no-such-scanner"):
        load_config(tmp_path / "agent.yml")


def test_legacy_semgrep_key_is_rejected(tmp_path):
    (tmp_path / "agent.yml").write_text("semgrep:\n  enabled: true\n")
    with pytest.raises(ConfigError, match="scanners"):
        load_config(tmp_path / "agent.yml")


def test_language_mismatch_is_deferred_not_failed(tmp_path):
    (tmp_path / "a.ts").write_text("export const a = 1;\n")
    spec = ScannerSpec(name="codeql", image="i", command=["x", "{sarif}"], languages=["java"])
    runnable, cells = plan_scanners([spec], scan_scope(tmp_path))
    assert runnable == [] and cells[0].subject == "scanner:codeql" and cells[0].state == LedgerState.deferred
    assert "java" in cells[0].reason


def test_no_scanner_is_recorded():
    runnable, cells = plan_scanners([], _snapshot())
    assert runnable == [] and cells[0].subject == "scanner:*" and cells[0].reason == "등록된 스캐너 없음"


def test_alerts_outside_snapshot_are_dropped():
    kept, cells = keep_snapshot_alerts([_alert("UserDao.java"), _alert("ground-truth-private/gt.java"),
                                        _alert("out/report.json")], _snapshot())
    assert [a.file for a in kept] == ["UserDao.java"] and "2건" in cells[0].reason
    assert cells[0].state == LedgerState.deferred and not cells[0].subject.startswith("scanner:")


def test_stale_sarif_is_removed_before_run(monkeypatch, tmp_path):
    (tmp_path / "scanners").mkdir()
    (tmp_path / "scanners" / "semgrep.sarif").write_text((FIX / "results.sarif").read_text())
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "boom"))
    outcome = run_scanner(_semgrep(), _snapshot(), tmp_path)
    assert outcome.alerts == [] and outcome.status == Capability.failed and "boom" in outcome.errors[0]


def test_timeout_is_partial(monkeypatch, tmp_path):
    def slow(*a, **k):
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr(subprocess, "run", slow)
    outcome = run_scanner(_semgrep().model_copy(update={"timeout_seconds": 1}), _snapshot(), tmp_path)
    assert outcome.status == Capability.partial and "시간" in outcome.errors[0]


def test_docker_missing_is_failed_with_reason(monkeypatch, tmp_path):
    def missing(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "run", missing)
    outcome = run_scanner(_semgrep(), _snapshot(), tmp_path)
    assert outcome.status == Capability.failed and "Docker" in outcome.errors[0]


def test_scan_without_scanner_reports_gaps_but_keeps_exit_code(fake, tmp_path):
    from conftest import make_config

    fake.responses.append({"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'})
    root = tmp_path / "t"
    root.mkdir()
    (root / "a.mjs").write_text("export const a = 1;\n")
    r = run_scan(root, design=[], out=tmp_path / "o", config=make_config(fake))
    assert any(c.state == LedgerState.deferred and "CWE-918" in c.subject for c in r.ledger)
    assert "검사 규칙 없음" in (tmp_path / "o" / "report.html").read_text()


def test_scan_uses_scanner_alerts(fake, tmp_path, monkeypatch):
    from conftest import make_config

    alert = Fact(kind="alert", file="app.mjs", line=1, tool="semgrep", detail={"cwe": "CWE-918", "rule": "r", "message": "m"})
    monkeypatch.setattr("agent.core.orchestrator.run_scanner",
                        lambda *a, **k: ScanOutcome(status=Capability.partial, alerts=[alert], errors=["규칙 오류"]))
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'})
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "app.mjs").write_text("x\n")
    r = run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_semgrep()]))
    assert r.findings[0].tool_confirmed and r.exit_code == 1
    assert any(c.subject == "scanner:semgrep" and c.state == LedgerState.not_seen and "규칙 오류" in c.reason
               for c in r.ledger)


def test_config_defaults_off():
    assert AgentConfig().scanners == []


@pytest.mark.docker
def test_real_container_finds_fixture(tmp_path):
    outcome = run_scanner(_semgrep().model_copy(update={"timeout_seconds": 300}), _snapshot(), tmp_path)
    assert outcome.status == Capability.supported, outcome.errors
    assert [(a.file, a.line, a.detail["cwe"]) for a in outcome.alerts] == [("UserDao.java", 10, "CWE-89")]
    assert (tmp_path / "scanners" / "semgrep.sarif").exists() and "CWE-89" in outcome.covered_cwes
    assert not (tmp_path / "scanners" / "semgrep-work").exists()


def test_codeql_definition_never_pulls_and_needs_java(tmp_path):
    spec = load_scanner("codeql", Path.cwd())
    args = docker_args(spec, _snapshot(), tmp_path, "n")
    assert args[args.index("--pull") + 1] == "never" and args[args.index("--platform") + 1] == "linux/amd64"
    assert spec.languages == ["java"] and spec.rules == [] and "--output=/out/codeql.sarif" in args[-1]
    assert args[args.index("--memory") + 1] == "8g"


@pytest.mark.codeql
def test_real_codeql_container_reports_coverage(tmp_path):
    out = run_scanner(load_scanner("codeql", Path.cwd()), _snapshot(), tmp_path)
    assert out.status == Capability.supported, out.errors
    assert "CWE-89" in out.covered_cwes and (tmp_path / "scanners" / "codeql.sarif").exists()
