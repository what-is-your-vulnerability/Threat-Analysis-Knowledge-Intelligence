"""DEV 설계문서에서 조건 D·E용 보안 규칙을 만든다. 입력은 designs/dev와 묶음의 API 목록뿐이고 정답을 읽지 않는다.

실험용이라 후보를 일괄 승인한다. 실제 프로젝트에서는 사람이 secagent rules approve로 승인한다.
실행: uv run python eval/derive_dev_rules.py --config 설정파일
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from agent.config import load_config
from agent.llm.gateway import LlmGateway
from agent.llm.roles import derive_rules, load_templates
from agent.schemas.models import RuleStatus
from agent.steps.scope import scan_scope
from agent.steps.slices import load_slices

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT.parent / "benchmarks" / "control-bench"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    snapshot = scan_scope(BENCH / "artifacts" / "DEV-D0" / "scan-input")
    slices = load_slices(ROOT / "eval" / "slices" / "dev.yml", snapshot)
    entrypoints = [f.flow_id for s in slices for f in s.flows]
    designs = sorted((BENCH / "designs" / "dev").glob("*.md"))
    gateway = LlmGateway(load_config(args.config), ROOT / "eval" / "runs" / "derive-dev-rules")
    derived = derive_rules(designs, entrypoints, load_templates(), gateway=gateway)
    for warning in derived.warnings:
        print(f"경고: {warning}")
    rows = []
    for rule in derived:
        rule.status = RuleStatus.approved
        rows.append(rule.model_dump(mode="json"))
    target = ROOT / "eval" / "rules" / "dev.yml"
    target.parent.mkdir(exist_ok=True)
    head = "# designs/dev/*.md에서 만든 실험용 규칙. 실험을 위해 일괄 승인했고 사람 검토 전이다(잠정).\n"
    target.write_text(head + yaml.safe_dump(rows, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"규칙 {len(rows)}개: {target}")


if __name__ == "__main__":
    main()
