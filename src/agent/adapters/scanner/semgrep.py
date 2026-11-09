"""Semgrep을 네트워크 없는 컨테이너에서 돌리고 결과를 공통 형식으로 바꾼다. 실패는 0건이 아니라 partial이나 failed다."""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel

from agent.schemas.models import Capability, Certainty, Fact, LedgerCell, LedgerState, Snapshot

CWE_RE = re.compile(r"CWE-\d+")
OUTPUT_NAME = "semgrep.sarif"
BUILTIN_RULES = Path(__file__).resolve().parents[4] / "rules" / "semgrep"
# 탐지 범위 밖 유형. AI가 판정하지 않고, 규칙이 없으면 못 본 범위로 알린다.
OUT_OF_SCOPE_CWES = {"CWE-918": "SSRF", "CWE-22": "경로 조작", "CWE-611": "XXE", "CWE-502": "역직렬화",
                     "CWE-352": "CSRF", "CWE-400": "서비스 거부"}


class SemgrepConfig(BaseModel):
    enabled: bool = False
    image: str = "semgrep/semgrep:1.183.0"
    rules: list[Path] = []  # 저장소 규칙에 더해 쓸 로컬 파일
    timeout_seconds: int = 600

    def rule_files(self) -> list[Path]:
        return [*sorted(BUILTIN_RULES.glob("*.yml")), *self.rules]


@dataclass
class ScanOutcome:
    status: Capability
    alerts: list[Fact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


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


def _relative(uri: str) -> str:
    return uri.removeprefix("file://").removeprefix("/src/").removeprefix("./")


def parse_sarif(path: Path) -> ScanOutcome:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return ScanOutcome(Capability.failed, errors=[f"결과 파일을 읽지 못함: {type(e).__name__}"])
    alerts: list[Fact] = []
    errors: list[str] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {r.get("id"): r for r in driver.get("rules", [])}
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                errors.append("도구가 실패로 끝남")
            errors += [n.get("message", {}).get("text", "") for n in invocation.get("toolExecutionNotifications", [])
                       if n.get("level") == "error"]
        for result in run.get("results", []):
            tags = rules.get(result.get("ruleId"), {}).get("properties", {}).get("tags", [])
            cwe = next((m.group(0) for tag in tags if (m := CWE_RE.search(str(tag)))), None)
            for location in result.get("locations", [])[:1]:
                physical = location.get("physicalLocation", {})
                region = physical.get("region", {})
                alerts.append(Fact(
                    kind="alert", file=_relative(physical.get("artifactLocation", {}).get("uri", "")),
                    line=region.get("startLine"), symbol=result.get("ruleId"), tool="semgrep",
                    tool_version=driver.get("semanticVersion"), certainty=Certainty.tool_confirmed,
                    detail={"rule": result.get("ruleId"), "cwe": cwe, "message": result.get("message", {}).get("text", ""),
                            "snippet": region.get("snippet", {}).get("text", "")},
                ))
    return ScanOutcome(Capability.partial if errors else Capability.supported, alerts, errors)


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
    outcome = parse_sarif(out / OUTPUT_NAME)
    if finished.returncode not in (0, 1):
        message = f"스캐너 종료 코드 {finished.returncode}: {finished.stderr[-300:]}"
        status = Capability.failed if outcome.status == Capability.failed else Capability.partial
        return ScanOutcome(status, outcome.alerts, [message, *outcome.errors])
    return outcome


def _rule_cwes(path: Path) -> set[str]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return set()
    return {m for rule in data.get("rules", []) for m in CWE_RE.findall(str(rule.get("metadata", {}).get("cwe", "")))}


def coverage_gaps(configs: list[Path]) -> list[LedgerCell]:
    """규칙이 없는 범위 밖 유형을 알린다. 탐지 범위 밖이라 경고로 치지 않고 deferred로 남긴다."""
    covered = {cwe for path in configs for cwe in _rule_cwes(path)}
    cells = [LedgerCell(subject=f"{name} ({cwe})", target="*", state=LedgerState.deferred, reason="이 유형은 검사 규칙 없음")
             for cwe, name in OUT_OF_SCOPE_CWES.items() if cwe not in covered]
    cells.append(LedgerCell(subject="의존성 CVE", target="*", state=LedgerState.deferred,
                            reason="이 유형은 검사 규칙 없음(라이브러리 점검은 다음 단계)"))
    return cells
