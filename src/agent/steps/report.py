"""결과를 report.json(원본), report.html, results.sarif, ledger.json으로 쓴다."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from agent.schemas.models import Capability, CaseSource, VerdictState
from agent.steps.paths import finding_paths
from agent.steps.sarif import to_sarif

STATE_LABELS = {"implemented": "구현 확인", "missing_suspected": "누락 의심", "unverified": "검증 불충분",
                "not_applicable": "해당 없음"}
OUTCOME_LABELS = {"pass": "통과", "warn": "경고", "block": "차단"}
RECHECK_LABELS = {"resolved": "해결 확인", "still": "남아 있음", "new": "새 문제", "unverifiable": "확인 불가",
                  "unstable": "결과가 흔들림"}
OVERALL = {0: ("통과", "pass"), 1: ("경고", "warn"), 2: ("차단", "block"), 3: ("실행 실패", "block")}


def _status(snapshot) -> str:
    if snapshot is None:
        return "failed"
    parts = set(snapshot.capabilities.values())
    if snapshot.status == Capability.supported and parts & {Capability.partial, Capability.unsupported, Capability.failed}:
        return Capability.partial.value  # 일부만 알아본 프로젝트를 "지원"으로 보이지 않게 한다
    return snapshot.status.value


def _count(items) -> dict[str, int]:
    return {s.value: sum(i.state == s for i in items) for s in VerdictState}


def write_report(result, out: Path) -> None:
    out = Path(out)
    snapshot = result.snapshot
    data = {
        # 서버 절대 경로는 화면·API로 내보내지 않고 폴더 이름만 남긴다.
        "target": Path(snapshot.root).resolve().name if snapshot else None,
        "commit": snapshot.commit if snapshot else None,
        "manifest_hash": snapshot.manifest_hash if snapshot else None,
        "mode": result.mode.value,
        "status": _status(snapshot),
        "capabilities": {k: v.value for k, v in snapshot.capabilities.items()} if snapshot else {},
        "exit_code": result.exit_code,
        "error": result.error,
        # verdicts는 조사 항목별 판정(구현 확인 포함), findings는 묶은 이슈(누락 의심·검증 불충분만)다.
        "summary": {"verdicts": _count(result.verdicts), "findings": _count(result.findings)},
        "findings":[f.model_dump(mode="json") for f in result.findings],
        "verdicts": [v.model_dump(mode="json") for v in result.verdicts],
        "cases": [c.model_dump(mode="json") for c in result.cases],
        "ledger": [c.model_dump(mode="json") for c in result.ledger],
        "recheck": [i.model_dump(mode="json") for i in result.recheck],
        "files": [f.path for f in snapshot.files] if snapshot else [],
        "not_read": [n.model_dump(mode="json") for n in snapshot.not_read] if snapshot else [],
        "slices": [{"name": s.name, "code_hash": s.code_hash, "truncated": s.truncated,
                    "capability": s.capability.value} for s in result.slices],
        "paths": finding_paths(result),
    }
    (out / "report.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "ledger.json").write_text(json.dumps(data["ledger"], ensure_ascii=False, indent=1), encoding="utf-8")

    problems = [v.evidence for v in result.verdicts if v.state == VerdictState.missing_suspected and v.evidence]
    (out / "results.sarif").write_text(
        json.dumps(to_sarif(problems, tool_name="secagent"), ensure_ascii=False, indent=1), encoding="utf-8")

    env = Environment(loader=FileSystemLoader(Path(__file__).parent), autoescape=True)
    label, css = OVERALL[result.exit_code]
    html = env.get_template("report.html.j2").render(
        **data,
        overall={"label": label, "css": css},
        state_labels=STATE_LABELS, outcome_labels=OUTCOME_LABELS, recheck_labels=RECHECK_LABELS,
        questions={c.case_id: f"고정 질문 · 묶음 {c.slice_id}" if c.source == CaseSource.question else c.question
                   for c in result.cases},
        not_seen=[c for c in data["ledger"] if c["state"] != "checked"],
        lens_answers=[c for c in data["ledger"]
                      if c["state"] == "checked" and c["reason"] and not c["subject"].startswith("scanner:")],
        truncated=[{"name": s.name, "reason": reason} for s in result.slices for reason in s.truncated],
    )
    (out / "report.html").write_text(html, encoding="utf-8")
