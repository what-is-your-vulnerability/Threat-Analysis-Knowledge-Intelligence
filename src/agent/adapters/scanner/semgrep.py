"""Semgrep을 네트워크 없는 컨테이너에서 돌리고 결과를 공통 형식으로 바꾼다. 실패는 0건이 아니라 partial이나 failed다."""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from pydantic import BaseModel

from agent.adapters.scanner.sarif import ScanOutcome, parse_sarif
from agent.schemas.models import Capability, Snapshot

OUTPUT_NAME = "semgrep.sarif"
BUILTIN_RULES = Path(__file__).resolve().parents[4] / "rules" / "semgrep"


class SemgrepConfig(BaseModel):
    enabled: bool = False
    image: str = "semgrep/semgrep:1.183.0"
    rules: list[Path] = []  # 저장소 규칙에 더해 쓸 로컬 파일
    timeout_seconds: int = 600

    def rule_files(self) -> list[Path]:
        return [*sorted(BUILTIN_RULES.glob("*.yml")), *self.rules]


def docker_args(snapshot: Snapshot, configs: list[Path], out: Path, image: str, name: str = "secagent-semgrep") -> list[str]:
    args = [
        "docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--memory", "4g",
        "--tmpfs", "/tmp", "-e", "HOME=/tmp", "-w", "/src",
        "-v", f"{snapshot.root}:/src:ro", "-v", f"{Path(out).resolve()}:/out",
    ]
    rules = []
    for number, config in enumerate(configs):
        args += ["-v", f"{Path(config).resolve()}:/rules/{number}.yml:ro"]
        rules += ["--config", f"/rules/{number}.yml"]
    return [*args, image, "semgrep", "scan", "--metrics=off", "--disable-version-check", "--sarif",
            "--output", f"/out/{OUTPUT_NAME}", *rules, "."]


def _remove_container(name: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
    except (subprocess.SubprocessError, OSError):
        pass  # 정리 실패가 시간 초과 보고를 가리지 않게 한다. 남은 컨테이너는 --network none이라 밖으로 못 나간다.


def run_semgrep(snapshot: Snapshot, config: SemgrepConfig, out: Path) -> ScanOutcome:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    name = f"secagent-semgrep-{uuid.uuid4().hex[:8]}"
    args = docker_args(snapshot, config.rule_files(), out, config.image, name)
    try:
        finished = subprocess.run(args, capture_output=True, text=True, timeout=config.timeout_seconds, check=False)
    except FileNotFoundError:
        return ScanOutcome(Capability.failed, errors=["Docker를 찾지 못해 스캐너를 실행하지 못함"])
    except subprocess.TimeoutExpired:
        _remove_container(name)
        return ScanOutcome(Capability.partial, errors=[f"시간 제한 {config.timeout_seconds}초를 넘겨 스캐너를 멈춤"])
    outcome = parse_sarif(out / OUTPUT_NAME, "semgrep")
    if finished.returncode not in (0, 1):
        message = f"스캐너 종료 코드 {finished.returncode}: {finished.stderr[-300:]}"
        status = Capability.failed if outcome.status == Capability.failed else Capability.partial
        return ScanOutcome(status, outcome.alerts, [message, *outcome.errors])
    return outcome

