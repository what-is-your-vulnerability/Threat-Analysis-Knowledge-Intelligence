"""설계문서에서 조건 D·E용 보안 규칙을 만든다. 입력은 설계문서와 대상 코드의 API 목록뿐이고 정답을 읽지 않는다.

실험용이라 후보를 일괄 승인한다. 실제 프로젝트에서는 사람이 taki rules approve로 승인한다.
실행: uv run python eval/derive_dev_rules.py --target ../taki-scan-target-a --design 설계.md \
    --out rules.yml --config 설정파일
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from taki.config import load_config
from taki.llm.gateway import LlmGateway
from taki.llm.roles import derive_rules, load_templates
from taki.schemas.models import RuleStatus
from taki.service import list_entrypoints

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True, help="scan-target 저장소를 받은 로컬 경로")
    parser.add_argument("--design", type=Path, nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    gateway = LlmGateway(load_config(args.config), ROOT / "eval" / "runs" / "derive-dev-rules")
    derived = derive_rules(args.design, list_entrypoints(args.target), load_templates(), gateway=gateway)
    for warning in derived.warnings:
        print(f"경고: {warning}")
    rows = []
    for rule in derived:
        rule.status = RuleStatus.approved
        rows.append(rule.model_dump(mode="json"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    head = "# 설계문서에서 만든 실험용 규칙. 실험을 위해 일괄 승인했고 사람 검토 전이다(잠정).\n"
    args.out.write_text(head + yaml.safe_dump(rows, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"규칙 {len(rows)}개: {args.out}")


if __name__ == "__main__":
    main()
