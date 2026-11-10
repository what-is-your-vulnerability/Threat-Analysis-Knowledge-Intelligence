"""이전 검사와 이번 검사를 비교한다. 파일이나 항목이 사라진 것을 해결로 치지 않는다."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

PROBLEM_STATES = {"missing_suspected", "unverified"}


class RecheckItem(BaseModel):
    case_id: str
    claim_key: str
    change: str  # resolved, still, new, unverifiable, unstable


def _load(run_dir: Path) -> dict:
    return json.loads((Path(run_dir) / "report.json").read_text(encoding="utf-8"))


def _root_files(verdict: dict) -> set[str]:
    return {h["file"] for h in (verdict.get("evidence") or {}).get("hops", [])}


def _change(before: dict, same_case: list[dict], files: set[str]) -> str:
    if not same_case or not _root_files(before) <= files:
        return "unverifiable"
    same_claim = [v for v in same_case if v["claim_key"] == before["claim_key"]]
    candidates = same_claim or same_case
    states = {v["state"] for v in candidates}
    if before["code_hash"] and before["code_hash"] in {v["code_hash"] for v in same_case} and before["state"] not in states:
        return "unstable"
    if "missing_suspected" in states:
        return "still"
    if "unverified" in states or "not_applicable" in states:
        return "unverifiable"
    return "resolved"


def compare_runs(previous: Path, current: Path) -> list[RecheckItem]:
    before_report, after_report = _load(previous), _load(current)
    after = after_report["verdicts"]
    files = set(after_report["files"])
    after_keys = {(v["case_id"], v["claim_key"]) for v in after}
    items = []
    handled = set()
    renamed_cases = set()
    for before in before_report["verdicts"]:
        if before["state"] not in PROBLEM_STATES:
            continue
        key = (before["case_id"], before["claim_key"])
        handled.add(key)
        if key not in after_keys:
            renamed_cases.add(before["case_id"])
        same_case = [v for v in after if v["case_id"] == before["case_id"]]
        items.append(RecheckItem(case_id=key[0], claim_key=key[1], change=_change(before, same_case, files)))
    for verdict in after:
        key = (verdict["case_id"], verdict["claim_key"])
        # 같은 항목에서 이름만 바뀐 주장은 위에서 이미 비교했다.
        if verdict["state"] in PROBLEM_STATES and key not in handled and key[0] not in renamed_cases:
            items.append(RecheckItem(case_id=key[0], claim_key=key[1], change="new"))
    items += _compare_scanner_findings(before_report, after_report)
    return items


def _compare_scanner_findings(before_report: dict, after_report: dict) -> list[RecheckItem]:
    """AI 조사 없이 도구 결과로만 실린 이슈를 비교한다. 스캐너가 정상 실행되지 않았으면 해결로 치지 않는다."""
    after_ids = {f["finding_id"] for f in after_report.get("findings", [])}
    # 스캐너가 하나도 없거나 실패했으면 해결로 치지 않는다. 언어가 안 맞아 건너뛴 도구는 상관없다.
    scanner_ok = not any(c["subject"] == "scanner:*" or (c["subject"].startswith("scanner:") and c["state"] == "not_seen")
                         for c in after_report.get("ledger", []))
    items = []
    for finding in before_report.get("findings", []):
        if not finding.get("tool_confirmed") or finding.get("case_ids"):
            continue
        change = "still" if finding["finding_id"] in after_ids else ("resolved" if scanner_ok else "unverifiable")
        items.append(RecheckItem(case_id=finding["finding_id"], claim_key="scanner", change=change))
    return items
