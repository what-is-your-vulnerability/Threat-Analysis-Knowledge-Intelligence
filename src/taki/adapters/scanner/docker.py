"""YAML로 등록한 SAST 도구를 네트워크 없는 컨테이너에서 돌리고 SARIF를 읽는다. 실패는 0건이 아니라 partial이나 failed다."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from taki.adapters.scanner.sarif import ScanOutcome, parse_sarif
from taki.errors import ConfigError
from taki.schemas.models import Capability, Fact, LedgerCell, LedgerState, Snapshot

SCANNER_DIR = Path(__file__).resolve().parents[4] / "rules" / "scanners"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
PLACEHOLDERS = {"sarif", "rules", "src", "work"}
DROPPED_REASONS = {"금지 폴더", "검사 결과 폴더", "제외 폴더", "심볼릭 링크"}  # 이 아래 파일의 경고는 버린다


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

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not NAME_RE.match(value):
            raise ValueError(f"이름은 소문자·숫자·-·_만 쓴다: {value}")
        return value

    @field_validator("command")
    @classmethod
    def _command(cls, value: list[str]) -> list[str]:
        used = {name for part in value for name in PLACEHOLDER_RE.findall(part)}
        if unknown := used - PLACEHOLDERS:
            raise ValueError(f"모르는 자리표시자: {sorted(unknown)}")
        if "sarif" not in used:
            raise ValueError("명령에 {sarif}(결과 파일 위치)가 없다")
        if any("{rules}" in part and part != "{rules}" for part in value):
            raise ValueError("{rules}는 명령의 한 항목으로만 쓴다")
        return value


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
    """이름(rules/scanners/<이름>.yml)이나 직접 쓴 정의를 읽는다. 규칙 경로는 정의가 적힌 곳 기준이다."""
    if isinstance(entry, ScannerSpec):
        return entry
    if isinstance(entry, str):
        path = SCANNER_DIR / f"{entry}.yml"
        if not NAME_RE.match(entry) or not path.exists():
            raise ConfigError(f"스캐너 정의가 없음: {entry} (rules/scanners/{entry}.yml)")
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
        return [], [LedgerCell(subject="scanner:*", target="*", state=LedgerState.deferred, reason="등록된 스캐너 없음")]
    languages = {f.language for f in snapshot.files}
    runnable, cells = [], []
    for spec in specs:
        if spec.languages and not languages & set(spec.languages):
            cells.append(LedgerCell(subject=f"scanner:{spec.name}", target="*", state=LedgerState.deferred,
                                    reason=f"대상 언어 파일 없음 ({', '.join(spec.languages)})"))
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
    return [arg for n in snapshot.not_read if n.reason in ("금지 폴더", "검사 결과 폴더")
            for arg in ("--mount", f"type=tmpfs,{_field(f'dst=/src/{n.path}')}")]


def docker_args(spec: ScannerSpec, snapshot: Snapshot, out: Path, name: str) -> list[str]:
    scan_dir = Path(out).resolve() / "scanners"
    args = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--memory", spec.memory,
            "--pull", spec.pull]
    if spec.platform:
        args += ["--platform", spec.platform]
    if hasattr(os, "getuid"):  # 이미지 사용자와 상관없이 붙인 폴더에 쓰고, 결과 파일이 root 소유로 남지 않게 한다
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    args += ["--tmpfs", "/tmp", "-e", "HOME=/tmp", "-w", "/src",
             *_bind(snapshot.root, "/src", readonly=True), *_hidden(snapshot), *_bind(scan_dir, "/out"),
             *_bind(scan_dir / f"{spec.name}-work", "/work")]
    rule_args: list[str] = []
    for number, rule in enumerate(spec.rules):
        target = f"/rules/{number}{rule.suffix}"
        args += _bind(rule, target, readonly=True)
        rule_args += [spec.rule_arg, target]
    values = {"sarif": f"/out/{spec.name}.sarif", "src": "/src", "work": "/work"}
    command: list[str] = []
    for part in spec.command:
        command += rule_args if part == "{rules}" else [PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], part)]
    return [*args, spec.image, *command]


def _remove_container(name: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
    except (subprocess.SubprocessError, OSError):
        pass  # 정리 실패가 시간 초과 보고를 가리지 않게 한다. 남은 컨테이너는 --network none이라 밖으로 못 나간다.


def run_scanner(spec: ScannerSpec, snapshot: Snapshot, out: Path) -> ScanOutcome:
    scan_dir = Path(out) / "scanners"
    work = scan_dir / f"{spec.name}-work"
    sarif = scan_dir / f"{spec.name}.sarif"
    work.mkdir(parents=True, exist_ok=True)
    sarif.unlink(missing_ok=True)  # 같은 --out을 다시 쓸 때 이전 결과를 읽지 않게 한다
    name = f"taki-{spec.name}-{uuid.uuid4().hex[:8]}"
    try:
        finished = subprocess.run(docker_args(spec, snapshot, out, name), capture_output=True, text=True,
                                  timeout=spec.timeout_seconds, check=False)
    except FileNotFoundError:
        return ScanOutcome(Capability.failed, errors=["Docker를 찾지 못해 스캐너를 실행하지 못함"])
    except subprocess.TimeoutExpired:
        _remove_container(name)
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
    return kept, [LedgerCell(subject="스캐너 경고 제외", target="*", state=LedgerState.deferred,
                             reason=f"분석 범위 밖 파일의 경고 {dropped}건 제외")]
