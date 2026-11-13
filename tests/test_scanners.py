import os
import subprocess
from pathlib import Path

import pytest

from taki.adapters.scanner.docker import (
    ScannerSpec,
    docker_args,
    keep_snapshot_alerts,
    load_scanner,
    plan_scanners,
    run_scanner,
)
from taki.adapters.scanner.sarif import ScanOutcome
from taki.config import RULES_DIR, AgentConfig, ConfigError, load_config
from taki.core.orchestrator import run_scan
from taki.schemas.models import Capability, Fact, LedgerState
from taki.steps.scope import scan_scope

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
    args = docker_args(_semgrep(), _snapshot(), tmp_path, "taki-semgrep-x")
    assert args[:2] == ["docker", "run"] and "--rm" in args and "--read-only" in args
    assert args[args.index("--network") + 1] == "none" and args[args.index("--pull") + 1] == "missing"
    assert f"type=bind,src={FIX / 'app'},dst=/src,readonly" in args and "/out/semgrep.sarif" in args
    assert args[args.index("--config") + 1] == "/rules/0.yml" and "{rules}" not in args and "-v" not in args
    assert "semgrep/semgrep:1.183.0" in args and "--metrics=off" in args


def test_docker_args_run_as_host_user(tmp_path, monkeypatch):
    args = docker_args(_semgrep(), _snapshot(), tmp_path, "n")
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    monkeypatch.delattr(os, "getuid")  # Windows에는 uid가 없다
    assert "--user" not in docker_args(_semgrep(), _snapshot(), tmp_path, "n")


def test_mount_path_with_comma_is_quoted(tmp_path):
    root = tmp_path / "a,b"
    root.mkdir()
    (root / "A.java").write_text("class A {}\n")
    args = docker_args(_semgrep(), scan_scope(root), tmp_path, "n")
    assert f'"src={root}",dst=/src,readonly' in " ".join(args)


def test_bad_scanner_yaml_stops_before_scan(tmp_path):
    for bad in (
        {"name": "a/b", "image": "i", "command": ["x", "{sarif}"]},
        {"name": "a", "image": "i", "command": ["x"]},
        {"name": "a", "image": "i", "command": ["x", "{sarif}", "{oops}"]},
        {"name": "a", "image": "i", "command": ["x", "--out={sarif}", "--config={rules}"]},
        {"name": "a", "image": "i", "command": ["x", "{sarif}"], "rules": ["nope/*.yml"]},
        {"name": "a", "image": "i", "command": ["x", "{sarif}"], "imgae": "typo"},
        "no-such-scanner",
        "../semgrep",
    ):
        with pytest.raises(ConfigError):
            load_scanner(bad, tmp_path)


def test_inline_definition_rules_are_relative_to_base(tmp_path):
    (tmp_path / "r.yml").write_text("rules: []\n")
    spec = load_scanner(
        {"name": "mine", "image": "i", "command": ["x", "{sarif}", "{rules}"], "rules": ["*.yml"]}, tmp_path
    )
    assert spec.rules == [(tmp_path / "r.yml").resolve()]


def test_config_loads_scanner_names(tmp_path):
    (tmp_path / "taki.yml").write_text("scanners: [semgrep]\n")
    assert [s.name for s in load_config(tmp_path / "taki.yml").scanners] == ["semgrep"]


def test_bad_scanner_in_config_is_config_error(tmp_path):
    (tmp_path / "taki.yml").write_text("scanners: [no-such-scanner]\n")
    with pytest.raises(ConfigError, match="no-such-scanner"):
        load_config(tmp_path / "taki.yml")


def test_legacy_semgrep_key_is_rejected(tmp_path):
    (tmp_path / "taki.yml").write_text("semgrep:\n  enabled: true\n")
    with pytest.raises(ConfigError, match="scanners"):
        load_config(tmp_path / "taki.yml")


def test_language_mismatch_is_deferred_not_failed(tmp_path):
    (tmp_path / "a.ts").write_text("export const a = 1;\n")
    spec = ScannerSpec(name="codeql", image="i", command=["x", "{sarif}"], languages=["java"])
    runnable, cells = plan_scanners([spec], scan_scope(tmp_path))
    assert runnable == [] and cells[0].subject == "scanner:codeql" and cells[0].state == LedgerState.deferred
    assert "java" in cells[0].reason


def test_no_scanner_is_recorded():
    runnable, cells = plan_scanners([], _snapshot())
    assert runnable == [] and cells[0].subject == "scanner:*" and cells[0].reason == "등록된 스캐너 없음"


def _hidden_target(tmp_path):
    root = tmp_path / "t"
    for folder in ("ground-truth-private", "node_modules/x", ".git", "o", "x,y/work"):
        (root / folder).mkdir(parents=True)
    (root / "ground-truth-private" / "gt.java").write_text("class G {}\n")
    (root / "UserDao.java").write_text("class U {}\n")
    return root, scan_scope(root, exclude=((root / "o").resolve(),))


def test_alerts_outside_snapshot_are_dropped(tmp_path):
    _, snapshot = _hidden_target(tmp_path)
    kept, cells = keep_snapshot_alerts(
        [
            _alert("UserDao.java"),
            _alert("ground-truth-private/gt.java"),
            _alert("o/report.json"),
            _alert("node_modules/x/a.js"),
        ],
        snapshot,
    )
    assert [a.file for a in kept] == ["UserDao.java"] and "3건" in cells[0].reason
    assert cells[0].state == LedgerState.deferred and not cells[0].subject.startswith("scanner:")


def test_alerts_on_unsupported_extensions_are_kept(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    for name in ("A.java", "a.jsp", "build.gradle", "conf.json"):
        (root / name).write_text("x\n")
    alerts = [
        _alert("a.jsp", "CWE-79"),
        _alert("build.gradle"),
        _alert("conf.json"),
        _alert("ground-truth-privateX.jsp"),
    ]
    kept, cells = keep_snapshot_alerts(alerts, scan_scope(root))
    assert kept == alerts and cells == []


def test_forbidden_and_result_folders_are_hidden_from_container(tmp_path):
    root, snapshot = _hidden_target(tmp_path)
    args = docker_args(_semgrep(), snapshot, root / "o", "n")
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
    assert "type=tmpfs,dst=/src/ground-truth-private" in mounts and "type=tmpfs,dst=/src/o" in mounts
    assert 'type=tmpfs,"dst=/src/x,y/work"' in mounts
    assert not any(".git" in m or "node_modules" in m for m in mounts)


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

    alert = Fact(
        kind="alert", file="app.mjs", line=1, tool="semgrep", detail={"cwe": "CWE-918", "rule": "r", "message": "m"}
    )
    monkeypatch.setattr(
        "taki.core.orchestrator.run_scanner",
        lambda *a, **k: ScanOutcome(status=Capability.partial, alerts=[alert], errors=["규칙 오류"]),
    )
    fake.responses.append({"match": "lens_id별로", "content": '{"claims": [], "dispositions": []}'})
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "app.mjs").write_text("x\n")
    r = run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=make_config(fake, scanners=[_semgrep()]))
    assert r.findings[0].tool_confirmed and r.exit_code == 1
    assert any(
        c.subject == "scanner:semgrep" and c.state == LedgerState.not_seen and "규칙 오류" in c.reason for c in r.ledger
    )


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
    assert spec.languages == ["java"] and spec.rules == [] and "--output=/out/codeql.sarif" in args
    # Docker VM(약 7.75GiB) 안에서 끝나도록: 컨테이너 6g, CodeQL --ram은 그보다 낮게, 스레드는 고정
    assert args[args.index("--memory") + 1] == "6g"
    prep = docker_args(spec, _snapshot(), tmp_path, "n", prepare=True)
    for step in (args, prep):
        assert step.count("--ram=4096") == 1 and step.count("--threads=4") == 1 and "--threads=0" not in step


def test_codeql_prepare_only_reaches_maven_central_through_proxy(tmp_path):
    # Java build-mode=none은 의존 jar를 Maven Central에서 받는다. 막으면 오류 없이 0건이 된다(11/13 시험).
    spec = load_scanner("codeql", Path.cwd())
    assert spec.prepare_allow_hosts == ["repo.maven.apache.org"]
    prep = docker_args(spec, _snapshot(), tmp_path, "n", prepare=True, network="taki-net-x", proxy_host="proxy")
    main = docker_args(spec, _snapshot(), tmp_path, "n", network="taki-net-x")
    assert prep[prep.index("--network") + 1] == "taki-net-x" and main[main.index("--network") + 1] == "none"
    assert prep[prep.index("taki-codeql:2.27.4") + 1 :][:3] == ["codeql", "database", "create"]
    assert main[main.index("taki-codeql:2.27.4") + 1 :][:3] == ["codeql", "database", "analyze"]
    envs = [prep[i + 1] for i, a in enumerate(prep) if a == "-e"]
    assert "CODEQL_PROXY_HOST=proxy" in envs and "CODEQL_PROXY_PORT=3128" in envs
    assert any(e.startswith("CODEQL_PROXY_URLS=") and "repo.maven.apache.org/maven2" in e for e in envs)
    assert not any(e.startswith("CODEQL_PROXY") for e in [main[i + 1] for i, a in enumerate(main) if a == "-e"])
    # 두 단계가 같은 /work를 쓰고, 둘 다 코드는 읽기 전용이며 루트 파일시스템도 읽기 전용이다
    for step in (prep, main):
        mounts = [step[i + 1] for i, a in enumerate(step) if a == "--mount"]
        assert any(m.endswith("dst=/work") for m in mounts) and any(m.endswith("dst=/src,readonly") for m in mounts)
        assert "--read-only" in step


def test_scanners_without_prepare_stay_offline(tmp_path):
    spec = _semgrep()
    assert spec.prepare == [] and spec.prepare_allow_hosts == [] and spec.prepare_env == {}
    args = docker_args(spec, _snapshot(), tmp_path, "n")
    assert args[args.index("--network") + 1] == "none"


@pytest.mark.parametrize(
    "update",
    [
        {"prepare_allow_hosts": ["repo.maven.apache.org"]},  # prepare 없이 호스트만
        {"prepare": ["true"], "prepare_allow_hosts": ["https://repo.maven.apache.org"]},  # 스킴
        {"prepare": ["true"], "prepare_allow_hosts": ["*.apache.org"]},  # 와일드카드
        {"prepare": ["true"], "prepare_allow_hosts": ["a.com,b.com"]},  # 쉼표
        {"prepare": ["true"], "prepare_env": {"X": "{proxy_host}"}},  # 프록시 없이 프록시 주소 사용
        {"prepare": ["true"], "prepare_env": {"BAD NAME": "1"}},
    ],
)
def test_bad_prepare_network_settings_are_rejected(update):
    with pytest.raises(ConfigError):
        load_scanner({**_semgrep().model_dump(mode="json"), "rules": [], **update}, Path.cwd())


class _FakeDocker:
    """docker 호출을 기록한다. fail에 든 하위 명령은 실패한다."""

    def __init__(self, tmp_path, fail=(), timeout_on=None):
        self.calls, self.fail, self.timeout_on, self.tmp_path = [], set(fail), timeout_on, tmp_path

    def __call__(self, args, **k):
        self.calls.append(list(args))
        sub = args[1]
        if sub == "run" and "--rm" in args and "-d" not in args and "--user" in args:  # 스캐너 컨테이너
            sub = "scan-prepare" if args[args.index("--network") + 1] != "none" else "scan-main"
            if sub == "scan-main":
                (self.tmp_path / "scanners" / "semgrep.sarif").write_text((FIX / "results.sarif").read_text())
        if sub == self.timeout_on:
            raise subprocess.TimeoutExpired("docker", 1)
        return subprocess.CompletedProcess(args, 3 if sub in self.fail else 0, "", f"{sub} failed")

    def subs(self):
        return [
            ("run-d" if c[1] == "run" and "-d" in c else c[1]) + (":" + c[2] if c[1] == "network" else "")
            for c in self.calls
        ]


def _proxied_spec():
    return _semgrep().model_copy(
        update={
            "prepare": ["true"],
            "prepare_allow_hosts": ["repo.maven.apache.org"],
            "prepare_env": {"P": "{proxy_host}"},
        }
    )


def test_prepare_runs_through_egress_proxy_and_cleans_up(monkeypatch, tmp_path):
    fake = _FakeDocker(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr("taki.adapters.scanner.docker.time.sleep", lambda s: None)
    outcome = run_scanner(_proxied_spec(), _snapshot(), tmp_path)
    assert outcome.status == Capability.supported, outcome.errors
    assert fake.subs() == [
        "network:create", "run-d", "network:connect", "exec", "run", "rm", "network:rm", "run",
    ]  # fmt: skip
    create, proxy, connect, _, prep, rm, netrm, main = fake.calls
    net = create[-1]
    assert "--internal" in create and netrm[-1] == net
    assert (
        "ALLOW_HOSTS=repo.maven.apache.org" in proxy
        and "taki-egress-proxy:1" in proxy
        and proxy[proxy.index("--network") + 1] == net
    )
    assert connect[-2:] == ["bridge", proxy[proxy.index("--name") + 1]] and rm[-1] == proxy[proxy.index("--name") + 1]
    assert prep[prep.index("--network") + 1] == net and "P=proxy" in prep
    assert main[main.index("--network") + 1] == "none"
    assert not (tmp_path / "scanners" / "semgrep-work").exists()


def test_prepare_failure_stops_the_scan_and_removes_the_proxy(monkeypatch, tmp_path):
    fake = _FakeDocker(tmp_path, fail={"scan-prepare"})
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr("taki.adapters.scanner.docker.time.sleep", lambda s: None)
    outcome = run_scanner(_proxied_spec(), _snapshot(), tmp_path)
    assert outcome.status == Capability.failed and "준비 단계" in outcome.errors[0]
    assert fake.subs()[-2:] == ["rm", "network:rm"] and "scan-main" not in [c[1] for c in fake.calls]
    assert not any(c[1] == "run" and "--user" in c and c[c.index("--network") + 1] == "none" for c in fake.calls)


def test_proxy_start_failure_fails_before_any_scan_container(monkeypatch, tmp_path):
    fake = _FakeDocker(tmp_path, fail={"run"})
    monkeypatch.setattr(subprocess, "run", fake)
    outcome = run_scanner(_proxied_spec(), _snapshot(), tmp_path)
    assert outcome.status == Capability.failed and "접속 제한" in outcome.errors[0]
    assert fake.subs()[-2:] == ["rm", "network:rm"]
    assert not any("--user" in c for c in fake.calls)  # 스캐너 컨테이너는 한 번도 안 뜸


def test_prepare_without_hosts_has_no_network_and_no_proxy(monkeypatch, tmp_path):
    fake = _FakeDocker(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake)
    spec = _semgrep().model_copy(update={"prepare": ["true"]})
    # 준비 단계와 검사 단계 모두 네트워크가 없고(none), 프록시·네트워크 생성은 없다.
    outcome = run_scanner(spec, _snapshot(), tmp_path)
    assert outcome.status == Capability.supported, outcome.errors
    assert len(fake.calls) == 2 and not any(c[1] == "network" for c in fake.calls)
    assert all(c[c.index("--network") + 1] == "none" for c in fake.calls)


def test_prepare_timeout_is_partial(monkeypatch, tmp_path):
    def slow(args, **k):
        if args[1] == "rm":
            return subprocess.CompletedProcess(args, 0, "", "")
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr(subprocess, "run", slow)
    spec = _semgrep().model_copy(update={"prepare": ["true"], "timeout_seconds": 1})
    outcome = run_scanner(spec, _snapshot(), tmp_path)
    assert outcome.status == Capability.partial and "시간" in outcome.errors[0]


@pytest.mark.codeql
def test_real_codeql_container_reports_coverage(tmp_path):
    out = run_scanner(load_scanner("codeql", Path.cwd()), _snapshot(), tmp_path)
    assert out.status == Capability.supported, out.errors
    assert "CWE-89" in out.covered_cwes and (tmp_path / "scanners" / "codeql.sarif").exists()
