"""YAML로 등록한 SAST 도구를 컨테이너에서 돌리고 SARIF를 읽는다.

검사 명령은 항상 네트워크 없이 돈다. 의존 라이브러리를 받아야 하는 도구는 정의에 준비 단계(prepare)를 적고,
접속할 호스트(prepare_allow_hosts)만 적는다. 준비 단계 컨테이너는 밖으로 직접 나가지 못하는 내부 네트워크에 있고,
허용 목록이 있는 프록시 컨테이너를 거쳐 그 호스트로만 나간다. 실패는 0건이 아니라 partial이나 failed다.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from taki.adapters.scanner.sarif import ScanOutcome, parse_sarif
from taki.errors import ConfigError
from taki.schemas.models import Capability, Fact, LedgerCell, LedgerState, Snapshot

SCANNER_DIR = Path(__file__).resolve().parents[2] / "rules" / "scanners"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
PLACEHOLDERS = {"sarif", "rules", "src", "work"}
DROPPED_REASONS = {"금지 폴더", "검사 결과 폴더", "제외 폴더", "심볼릭 링크"}  # 이 아래 파일의 경고는 버린다
# 준비 단계가 나갈 수 있는 곳을 허용 호스트로 제한하는 프록시 이미지.
# deploy/scanners/egress-proxy/Dockerfile로 로컬에서 빌드한다.
EGRESS_PROXY_IMAGE = "taki-egress-proxy:1"
EGRESS_PROXY_PORT = 3128
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")  # 스킴·경로·와일드카드 없는 호스트 이름만
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ENV_PLACEHOLDERS = {"{proxy_host}", "{proxy_port}"}


class ScannerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")  # YAML 오타를 조용히 무시하지 않는다.

    name: str
    image: str
    command: list[str]
    rules: list[Path] = []  # load_scanner가 펼친 절대 경로
    rule_arg: str = "--config"
    languages: list[str] = []  # 비어 있으면 언어와 무관하게 돈다
    platform: str | None = None
    pull: Literal["missing", "never"] = "missing"  # 로컬에서 빌드한 이미지는 never로 레지스트리에서 받지 않는다
    memory: str = "4g"
    timeout_seconds: int = 600
    # 검사 명령 전에 별도 컨테이너로 돌리는 준비 단계. 같은 /work를 공유한다. 비어 있으면 준비 단계가 없다.
    prepare: list[str] = []
    # 준비 단계가 접속할 수 있는 호스트. 비어 있으면 준비 단계도 네트워크가 없다. 검사 명령(command)은 항상 막는다.
    prepare_allow_hosts: list[str] = []
    # 준비 단계 환경 변수. 값의 {proxy_host}, {proxy_port}는 프록시 주소로 바뀐다.
    prepare_env: dict[str, str] = {}

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not NAME_RE.match(value):
            raise ValueError(f"이름은 소문자·숫자·-·_만 쓴다: {value}")
        return value

    @field_validator("command")
    @classmethod
    def _command(cls, value: list[str]) -> list[str]:
        used = _placeholders(value)
        if "sarif" not in used:
            raise ValueError("명령에 {sarif}(결과 파일 위치)가 없다")
        return value

    @field_validator("prepare")
    @classmethod
    def _prepare(cls, value: list[str]) -> list[str]:
        _placeholders(value)
        return value

    @field_validator("prepare_allow_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        for host in value:
            if not HOST_RE.match(host) or ".." in host:
                raise ValueError(f"허용 호스트는 소문자 호스트 이름만 쓴다(스킴·경로·와일드카드 불가): {host!r}")
        return value

    @field_validator("prepare_env")
    @classmethod
    def _env(cls, value: dict[str, str]) -> dict[str, str]:
        for key in value:
            if not ENV_NAME_RE.match(key):
                raise ValueError(f"환경 변수 이름이 올바르지 않다: {key!r}")
        return value

    @model_validator(mode="after")
    def _network_needs_prepare(self) -> ScannerSpec:
        if (self.prepare_allow_hosts or self.prepare_env) and not self.prepare:
            raise ValueError("prepare_allow_hosts와 prepare_env는 prepare 단계가 있을 때만 쓴다")
        uses_proxy = any(p in v for v in self.prepare_env.values() for p in ENV_PLACEHOLDERS)
        if uses_proxy and not self.prepare_allow_hosts:
            raise ValueError("{proxy_host}·{proxy_port}는 prepare_allow_hosts가 있을 때만 쓴다")
        return self


def _placeholders(value: list[str]) -> set[str]:
    used = {name for part in value for name in PLACEHOLDER_RE.findall(part)}
    if unknown := used - PLACEHOLDERS:
        raise ValueError(f"모르는 자리표시자: {sorted(unknown)}")
    if any("{rules}" in part and part != "{rules}" for part in value):
        raise ValueError("{rules}는 명령의 한 항목으로만 쓴다")
    return used


def _expand(patterns, base: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        full = Path(pattern) if Path(pattern).is_absolute() else base / pattern
        found = sorted(full.parent.glob(full.name))
        if not found:
            raise ConfigError(f"규칙 파일이 없음: {pattern}")
        files += [f.resolve() for f in found]
    return files


def load_scanner(entry, base: Path) -> ScannerSpec:
    """이름(src/taki/rules/scanners/<이름>.yml)이나 직접 쓴 정의를 읽는다. 규칙 경로는 정의가 적힌 곳 기준이다."""
    if isinstance(entry, ScannerSpec):
        return entry
    if isinstance(entry, str):
        path = SCANNER_DIR / f"{entry}.yml"
        if not NAME_RE.match(entry) or not path.exists():
            raise ConfigError(f"스캐너 정의가 없음: {entry} ({path})")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"스캐너 정의를 읽지 못함: {entry}: {e}") from e
        where, base = entry, path.parent
    elif isinstance(entry, dict):
        data, where = entry, entry.get("name", "?")
    else:
        raise ConfigError(f"스캐너 항목은 이름이나 정의여야 한다: {entry!r}")
    try:
        return ScannerSpec.model_validate({**data, "rules": _expand(data.get("rules", []), base)})
    except ValidationError as e:
        raise ConfigError(f"스캐너 정의 {where}: {e}") from e


def plan_scanners(specs: list[ScannerSpec], snapshot: Snapshot) -> tuple[list[ScannerSpec], list[LedgerCell]]:
    if not specs:
        return [], [
            LedgerCell(subject="scanner:*", target="*", state=LedgerState.deferred, reason="등록된 스캐너 없음")
        ]
    languages = {f.language for f in snapshot.files}
    runnable, cells = [], []
    for spec in specs:
        if spec.languages and not languages & set(spec.languages):
            cells.append(
                LedgerCell(
                    subject=f"scanner:{spec.name}",
                    target="*",
                    state=LedgerState.deferred,
                    reason=f"대상 언어 파일 없음 ({', '.join(spec.languages)})",
                )
            )
        else:
            runnable.append(spec)
    return runnable, cells


def _field(text: str) -> str:
    # --mount 값은 CSV라 쉼표나 따옴표가 든 경로는 따옴표로 감싼다
    return '"' + text.replace('"', '""') + '"' if "," in text or '"' in text else text


def _bind(src: Path, dst: str, readonly: bool = False) -> list[str]:
    return ["--mount", f"type=bind,{_field(f'src={src}')},dst={dst}" + (",readonly" if readonly else "")]


def _hidden(snapshot: Snapshot) -> list[str]:
    # 정답·결과 폴더는 컨테이너 안에서 빈 폴더로 가린다. .git 같은 제외 폴더는 도구가 쓸 수 있어 그대로 둔다.
    return [
        arg
        for n in snapshot.not_read
        if n.reason in ("금지 폴더", "검사 결과 폴더")
        for arg in ("--mount", f"type=tmpfs,{_field(f'dst=/src/{n.path}')}")
    ]


def docker_args(
    spec: ScannerSpec,
    snapshot: Snapshot,
    out: Path,
    name: str,
    *,
    prepare: bool = False,
    network: str = "none",
    proxy_host: str = "proxy",
) -> list[str]:
    """prepare=True면 준비 단계 컨테이너, 아니면 검사 컨테이너다. 검사 컨테이너는 항상 네트워크를 막는다.

    준비 단계의 network는 호출한 쪽이 만든 내부 네트워크 이름이다(허용 호스트가 없으면 none).
    """
    if not prepare:
        network = "none"
    scan_dir = Path(out).resolve() / "scanners"
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--memory",
        spec.memory,
        "--pull",
        spec.pull,
    ]
    if spec.platform:
        args += ["--platform", spec.platform]
    if hasattr(os, "getuid"):  # 이미지 사용자와 상관없이 붙인 폴더에 쓰고, 결과 파일이 root 소유로 남지 않게 한다
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    args += ["--tmpfs", "/tmp", "-e", "HOME=/tmp"]  # noqa: S108 호스트가 아니라 컨테이너 안 경로(tmpfs)다
    if prepare:
        for key, value in spec.prepare_env.items():
            value = value.replace("{proxy_host}", proxy_host).replace("{proxy_port}", str(EGRESS_PROXY_PORT))
            args += ["-e", f"{key}={value}"]
    args += [
        "-w",
        "/src",
        *_bind(snapshot.root, "/src", readonly=True),
        *_hidden(snapshot),
        *_bind(scan_dir, "/out"),
        *_bind(scan_dir / f"{spec.name}-work", "/work"),
    ]
    rule_args: list[str] = []
    for number, rule in enumerate(spec.rules):
        target = f"/rules/{number}{rule.suffix}"
        args += _bind(rule, target, readonly=True)
        rule_args += [spec.rule_arg, target]
    values = {"sarif": f"/out/{spec.name}.sarif", "src": "/src", "work": "/work"}
    command: list[str] = []
    for part in spec.prepare if prepare else spec.command:
        command += rule_args if part == "{rules}" else [PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], part)]
    return [*args, spec.image, *command]


def _remove_container(name: str) -> None:
    # 정리 실패가 시간 초과 보고를 가리지 않게 한다. 남은 컨테이너는 --network none이라 밖으로 못 나간다.
    with contextlib.suppress(subprocess.SubprocessError, OSError):
        # 고정 인자 목록, 셸 없음. name은 이 모듈이 만든 컨테이너 이름
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)  # noqa: S603, S607


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    # 고정 인자 목록, 셸 없음. 이름은 이 모듈이 만든 값이다
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603, S607


class EgressProxyError(RuntimeError):
    pass


@contextlib.contextmanager
def _egress_proxy(hosts: list[str]) -> Iterator[str]:
    """허용 호스트로만 나가는 프록시를 띄우고, 준비 단계 컨테이너가 붙을 내부 네트워크 이름을 돌려준다.

    내부 네트워크(--internal)에는 외부로 나가는 길이 없다. 프록시만 외부 네트워크에도 붙어 있고,
    허용 호스트 밖은 막는다. 끝나면 프록시와 네트워크를 지운다.
    """
    suffix = uuid.uuid4().hex[:8]
    net, proxy = f"taki-net-{suffix}", f"taki-proxy-{suffix}"
    try:
        if (made := _docker("network", "create", "--internal", net)).returncode != 0:
            raise EgressProxyError(f"내부 네트워크를 만들지 못함: {made.stderr[-200:]}")
        started = _docker(
            *["run", "-d", "--rm", "--name", proxy, "--pull", "never", "--read-only", "--tmpfs", "/tmp"],  # noqa: S108
            *["--memory", "256m", "--network", net, "--network-alias", "proxy"],
            *["-e", f"ALLOW_HOSTS={','.join(hosts)}", EGRESS_PROXY_IMAGE],
        )
        if started.returncode != 0:
            raise EgressProxyError(f"프록시 컨테이너를 띄우지 못함: {started.stderr[-200:]}")
        if (joined := _docker("network", "connect", "bridge", proxy)).returncode != 0:
            raise EgressProxyError(f"프록시를 외부 네트워크에 붙이지 못함: {joined.stderr[-200:]}")
        for _ in range(20):  # 최대 약 10초. 프록시가 요청을 받을 준비가 되면 로그에 남는다
            ready = _docker("exec", proxy, "sh", "-c", "grep -q 'Starting main loop' /tmp/tinyproxy.log")
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise EgressProxyError("프록시가 시간 안에 준비되지 않음")
        yield net
    finally:
        _docker("rm", "-f", proxy)
        _docker("network", "rm", net)


def _run_step(
    spec: ScannerSpec, snapshot: Snapshot, out: Path, deadline: float, *, prepare: bool, network: str = "none"
) -> subprocess.CompletedProcess[str]:
    """컨테이너 한 단계를 돌린다. 남은 시간(deadline)을 넘기면 컨테이너를 지우고 TimeoutExpired를 올린다."""
    name = f"taki-{spec.name}-{uuid.uuid4().hex[:8]}"
    try:
        # 인자 목록, 셸 없음. 이미지·명령은 등록한 스캐너 정의에서 오고 검증을 거친다
        return subprocess.run(  # noqa: S603
            docker_args(spec, snapshot, out, name, prepare=prepare, network=network),
            capture_output=True,
            text=True,
            timeout=max(deadline - time.monotonic(), 1),
            check=False,
        )
    except subprocess.TimeoutExpired:
        _remove_container(name)
        raise


def run_scanner(spec: ScannerSpec, snapshot: Snapshot, out: Path) -> ScanOutcome:
    scan_dir = Path(out) / "scanners"
    work = scan_dir / f"{spec.name}-work"
    sarif = scan_dir / f"{spec.name}.sarif"
    work.mkdir(parents=True, exist_ok=True)
    sarif.unlink(missing_ok=True)  # 같은 --out을 다시 쓸 때 이전 결과를 읽지 않게 한다
    deadline = time.monotonic() + spec.timeout_seconds  # 준비 단계와 검사 단계가 함께 쓰는 제한 시간
    try:
        if spec.prepare:
            if spec.prepare_allow_hosts:
                with _egress_proxy(spec.prepare_allow_hosts) as net:
                    prepared = _run_step(spec, snapshot, out, deadline, prepare=True, network=net)
            else:
                prepared = _run_step(spec, snapshot, out, deadline, prepare=True)
            if prepared.returncode != 0:
                message = f"스캐너 준비 단계 종료 코드 {prepared.returncode}: {prepared.stderr[-300:]}"
                return ScanOutcome(Capability.failed, errors=[message])
        finished = _run_step(spec, snapshot, out, deadline, prepare=False)
    except FileNotFoundError:
        return ScanOutcome(Capability.failed, errors=["Docker를 찾지 못해 스캐너를 실행하지 못함"])
    except EgressProxyError as e:
        return ScanOutcome(Capability.failed, errors=[f"스캐너 준비 단계의 접속 제한을 만들지 못함: {e}"])
    except subprocess.TimeoutExpired:
        return ScanOutcome(Capability.partial, errors=[f"시간 제한 {spec.timeout_seconds}초를 넘겨 스캐너를 멈춤"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    outcome = parse_sarif(sarif, spec.name)
    if finished.returncode not in (0, 1):
        message = f"스캐너 종료 코드 {finished.returncode}: {finished.stderr[-300:]}"
        status = Capability.failed if outcome.status == Capability.failed else Capability.partial
        return ScanOutcome(status, outcome.alerts, [message, *outcome.errors], outcome.covered_cwes)
    return outcome


def keep_snapshot_alerts(alerts: list[Fact], snapshot: Snapshot) -> tuple[list[Fact], list[LedgerCell]]:
    """금지·결과·제외 폴더와 심볼릭 링크 아래 파일의 경고를 뺀다. 확장자를 모르는 파일의 경고는 도구 결과로 남긴다."""
    hidden = [n.path for n in snapshot.not_read if n.reason in DROPPED_REASONS]
    kept = [a for a in alerts if not any(a.file == p or a.file.startswith(f"{p}/") for p in hidden)]
    dropped = len(alerts) - len(kept)
    if not dropped:
        return kept, []
    return kept, [
        LedgerCell(
            subject="스캐너 경고 제외",
            target="*",
            state=LedgerState.deferred,
            reason=f"분석 범위 밖 파일의 경고 {dropped}건 제외",
        )
    ]
