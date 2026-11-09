"""조건별 결과를 채점한다. 정답 파일은 기존 채점기(score_tools.py)를 통해 이 스크립트에서만 읽는다.

실행: uv run python eval/score.py <실험> <조건>
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT.parent / "benchmarks" / "control-bench"


def _write_stability(out: Path) -> None:
    flagged: dict[tuple[str, str, str], list[bool]] = defaultdict(list)
    with (out / "row-hits.csv").open(newline="") as f:
        for row in csv.DictReader(f):
            if row["tool"] != "UNION":
                key = (row["variant_id"], row["instance_id"], row["expected_state"])
                flagged[key].append(row["flagged"] == "True")
    with (out / "stability.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["variant_id", "instance_id", "expected_state", "runs", "flagged_runs", "stable"])
        for (variant, instance, state), values in sorted(flagged.items()):
            writer.writerow([variant, instance, state, len(values), sum(values), len(set(values)) == 1])


def score(runs: Path, out: Path) -> None:
    # 조건마다 폴더가 달라 UNION 행은 그 조건의 회차 합집합이고, 조건을 합친 값이 아니다.
    spec = importlib.util.spec_from_file_location("score_tools", BENCH / "scripts" / "score_tools.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RUNS, module.OUT = Path(runs), Path(out)
    module.main()
    _write_stability(Path(out))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("experiment")
    parser.add_argument("condition")
    args = parser.parse_args()
    score(ROOT / "eval" / "runs" / args.experiment / args.condition,
          ROOT / "eval" / "reports" / args.experiment / args.condition)


if __name__ == "__main__":
    main()
