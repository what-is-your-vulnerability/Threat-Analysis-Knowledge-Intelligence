"""명령줄 입구. 종료 코드: 0 통과, 1 경고, 2 차단, 3 실행 실패."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent.adapters.repo.local import ForbiddenPathError
from agent.config import ConfigError, load_config
from agent.core.orchestrator import RunResult, run_scan
from agent.schemas.models import RunMode
from agent.steps.cases import load_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secagent", description="보안 통제 구현 여부를 근거와 함께 진단한다.")
    commands = parser.add_subparsers(dest="command", required=True)
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
    print(f"리포트: {result.out / 'report.html'} (종료 코드 {result.exit_code})")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_scan(
            args.target, design=args.design, out=args.out, config=load_config(args.config),
            mode=RunMode.recheck if args.command == "recheck" else RunMode.full,
            slices_file=args.slices, rules=load_rules(args.rules) if args.rules else [],
            previous=getattr(args, "previous", None),
        )
    except (ConfigError, ForbiddenPathError, FileNotFoundError) as e:
        print(f"실행 실패: {e}", file=sys.stderr)
        return 3
    _print_summary(result)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
