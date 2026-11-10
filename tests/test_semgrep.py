import subprocess
from pathlib import Path

import pytest

from agent.adapters.scanner.sarif import ScanOutcome
from agent.adapters.scanner.semgrep import SemgrepConfig, docker_args, run_semgrep
from agent.config import RULES_DIR, AgentConfig
from agent.core.orchestrator import run_scan
from agent.schemas.models import Capability, LedgerState
from agent.steps.scope import scan_scope

FIX = Path(__file__).parent / "fixtures" / "semgrep"
IMAGE = "semgrep/semgrep:1.183.0"


def _snapshot():
    return scan_scope(FIX / "app")


def test_docker_args_block_network(tmp_path):
    args = docker_args(_snapshot(), [RULES_DIR / "semgrep" / "java-sql.yml"], tmp_path, IMAGE)
    joined = " ".join(args)
    assert args[:2] == ["docker", "run"] and "--rm" in args and "--read-only" in args
    assert args[args.index("--network") + 1] == "none" and args[args.index("--memory") + 1] == "4g"
    assert f"{FIX / 'app'}:/src:ro" in joined and IMAGE in args and "--metrics=off" in args
    assert "--config" in args and args[args.index("--config") + 1].startswith("/rules/")


def _config(tmp_path=None, **kw):
    return SemgrepConfig(enabled=True, image=IMAGE, **kw)


def test_timeout_is_partial(monkeypatch, tmp_path):
    def slow(*a, **k):
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr(subprocess, "run", slow)
    outcome = run_semgrep(_snapshot(), _config(timeout_seconds=1), tmp_path)
    assert outcome.status == Capability.partial and "시간" in outcome.errors[0]


def test_docker_missing_is_failed_with_reason(monkeypatch, tmp_path):
    def missing(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "run", missing)
    outcome = run_semgrep(_snapshot(), _config(), tmp_path)
    assert outcome.status == Capability.failed and "Docker" in outcome.errors[0]


def test_tool_error_exit_code_without_output_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "boom"))
    outcome = run_semgrep(_snapshot(), _config(), tmp_path)
    assert outcome.status == Capability.failed and "boom" in outcome.errors[0]


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

    from agent.schemas.models import Fact

    alert = Fact(kind="alert", file="app.mjs", line=1, tool="semgrep", detail={"cwe": "CWE-918", "rule": "r", "message": "m"})
    monkeypatch.setattr("agent.core.orchestrator.run_semgrep",
                        lambda *a, **k: ScanOutcome(status=Capability.partial, alerts=[alert], errors=["규칙 오류"]))
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'})
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "app.mjs").write_text("x\n")
    config = make_config(fake, semgrep=SemgrepConfig(enabled=True, image=IMAGE))
    r = run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=config)
    assert r.findings[0].tool_confirmed and r.exit_code == 1
    assert any(c.state == LedgerState.not_seen and "규칙 오류" in c.reason for c in r.ledger)


def test_config_defaults_off():
    assert AgentConfig().semgrep.enabled is False


@pytest.mark.docker
def test_real_container_finds_fixture(tmp_path):
    outcome = run_semgrep(_snapshot(), SemgrepConfig(enabled=True, image=IMAGE, timeout_seconds=300), tmp_path)
    assert outcome.status == Capability.supported, outcome.errors
    assert [(a.file, a.line, a.detail["cwe"]) for a in outcome.alerts] == [("UserDao.java", 10, "CWE-89")]
    assert (tmp_path / "semgrep.sarif").exists() and "CWE-89" in outcome.covered_cwes
