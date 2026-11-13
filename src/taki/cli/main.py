"""명령줄 입구. 종료 코드: 0 통과, 1 경고, 2 차단, 3 실행 실패."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from taki.adapters.repo.local import ForbiddenPathError, check_allowed, open_target
from taki.config import ConfigError, load_config
from taki.core.orchestrator import RunResult, run_scan
from taki.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, SecretLeft
from taki.schemas.models import RuleStatus, RunMode, SecurityRule
from taki.service import derive_project_rules
from taki.steps.cases import load_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taki", description="보안 통제 구현 여부를 근거와 함께 진단한다.")
    commands = parser.add_subparsers(dest="command", required=True)
    rules = commands.add_parser("rules").add_subparsers(dest="rules_command", required=True)
    derive = rules.add_parser("derive")
    derive.add_argument("target", type=Path)
    derive.add_argument("--design", type=Path, action="append", required=True)
    derive.add_argument("--out", type=Path, required=True)
    derive.add_argument("--config", type=Path)
    approve = rules.add_parser("approve")
    approve.add_argument("file", type=Path)
    approve.add_argument("--id", action="append", default=[])
    approve.add_argument("--all", action="store_true")
    for name in ("scan", "recheck"):
        sub = commands.add_parser(name)
        sub.add_argument("target", type=Path)
        sub.add_argument("--out", type=Path, required=True)
        sub.add_argument("--design", type=Path, action="append", default=[])
        sub.add_argument("--slices", type=Path)
        sub.add_argument("--rules", type=Path)
        sub.add_argument("--config", type=Path)
        if name == "recheck":
            sub.add_argument("--previous", type=Path, required=True)
    return parser


def _print_summary(result: RunResult) -> None:
    for f in result.findings:
        print(f"[{f.state.value}] {f.root_file or '-'} {f.root_symbol or ''} {f.cwe or ''}: {f.statement}")
    for item in result.recheck:
        print(f"[recheck] {item.case_id} {item.change}")
    report = result.out / "report.html" if result.out else "-"
    print(f"리포트: {report} (종료 코드 {result.exit_code})")


def _derive(args) -> int:
    for path in args.design:
        check_allowed(path.resolve())
    workdir = args.out.parent
    target = open_target(args.target, workdir / "_target")
    config = load_config(args.config)
    # 이미 승인한 규칙은 남기고, 승인 전 후보만 새 후보로 바꾼다.
    existing = load_rules(args.out) if args.out.exists() else []
    derived = derive_project_rules(args.design, target, [r.rule_id for r in existing], config, workdir)
    approved = [r for r in existing if r.status == RuleStatus.approved]
    _write_rules(args.out, [*approved, *derived])
    args.out.with_suffix(".threats.yml").write_text(
        yaml.safe_dump(derived.threats, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    for warning in derived.warnings:
        print(f"경고: {warning}", file=sys.stderr)
    print(f"규칙 후보 {len(derived)}개: {args.out} (승인 전에는 검사에 쓰이지 않음)")
    return 0


def _write_rules(path: Path, rules: list[SecurityRule]) -> None:
    rows = [r.model_dump(mode="json") for r in rules]
    path.write_text(yaml.safe_dump(rows, allow_unicode=True, sort_keys=False), encoding="utf-8")


def _approve(args) -> int:
    rules = load_rules(args.file)
    known = {r.rule_id for r in rules}
    unknown = [i for i in args.id if i not in known]
    if unknown or not (args.id or args.all):
        print(f"실행 실패: 승인할 규칙을 찾지 못함 {unknown}", file=sys.stderr)
        return 3
    for rule in rules:
        if (args.all or rule.rule_id in args.id) and rule.status != RuleStatus.approved:
            rule.status = RuleStatus.approved
            rule.version += 1
    _write_rules(args.file, rules)
    print(f"승인됨: {sum(r.status == RuleStatus.approved for r in rules)}/{len(rules)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "rules":
            return _derive(args) if args.rules_command == "derive" else _approve(args)
        result = run_scan(
            args.target,
            design=args.design,
            out=args.out,
            config=load_config(args.config),
            mode=RunMode.recheck if args.command == "recheck" else RunMode.full,
            slices_file=args.slices,
            rules=load_rules(args.rules) if args.rules else [],
            previous=getattr(args, "previous", None),
        )
    except (
        ConfigError,
        ForbiddenPathError,
        FileNotFoundError,
        LlmCallError,
        LlmFormatError,
        BudgetExceeded,
        SecretLeft,
    ) as e:
        print(f"실행 실패: {e}", file=sys.stderr)
        return 3
    except Exception as e:  # noqa: BLE001 - 예상 못 한 실패도 CI에서 경고(1)로 읽히지 않게 실행 실패로 끝낸다.
        print(f"실행 실패: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    _print_summary(result)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
