"""조건별 평가 실행기. 정답을 읽지 않고 scan-input과 기능 묶음만 입력으로 쓴다.

실행: uv run python eval/run.py --condition C --variant DEV-D0 --repeat 3 --experiment bc
모델이 설정되지 않으면 호출 없이 실패한다.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import yaml

from taki.adapters.repo.local import open_target
from taki.config import load_config
from taki.core.orchestrator import run_scan
from taki.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from taki.llm.roles import investigate
from taki.schemas.models import (
    Budget,
    Case,
    CaseSource,
    LedgerState,
    Slice,
    SliceFile,
    VerdictState,
    make_case_id,
)
from taki.steps.cases import QUESTION_SUBJECT, build_cases, load_rules
from taki.steps.lenses import load_lenses, render_questions
from taki.steps.sarif import to_sarif
from taki.steps.scope import scan_scope
from taki.steps.slices import load_slices, render_slice

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT.parent / "benchmarks" / "control-bench"
LLM_ERRORS = (LlmCallError, LlmFormatError, BudgetExceeded, SecretLeft)


def _ask(case, slice_, snapshot, gateway, record, claims, requirement=None):
    """조사 한 번을 돌려 주장을 모은다. 실패는 0건으로 치지 않고 기록한다."""
    try:
        result = investigate(case, render_slice(slice_, snapshot), gateway=gateway, requirement=requirement,
                             sent_files=[f.path for f in slice_.files])
    except LLM_ERRORS as e:
        record["errors"].append(f"{slice_.name}: {type(e).__name__}: {e}")
        return False
    claims.extend(result.claims)
    record["dispositions"] += [d.model_dump(mode="json") | {"slice": slice_.name} for d in result.dispositions]
    return True


def _run_b(snapshot, gateway, settings, record, claims) -> bool:
    budget = Budget(max_input_tokens=settings["max_input_tokens"], max_seconds=settings.get("max_seconds", 180),
                    max_output_tokens=settings.get("max_output_tokens", 6000))
    files = [f.path for f in snapshot.files if Path(f.path).suffix in settings["extensions"]]
    case = Case(case_id=make_case_id(CaseSource.question, QUESTION_SUBJECT, "all"), source=CaseSource.question,
                subject_id=QUESTION_SUBJECT, question=render_questions(load_lenses()), slice_id="all", budget=budget)
    whole = Slice(slice_id="all", name="all", files=[SliceFile(path=p) for p in files])
    if _ask(case, whole, snapshot, gateway, record, claims):
        return True
    if not record["errors"][-1].startswith("all: BudgetExceeded"):
        return True  # 호출 실패는 partial/failed로 처리한다.

    # 조용히 자르지 않는다. 입력을 줄였다는 사실을 status와 input에 남긴다.
    record["status"], record["input"] = "TOO_LARGE", "server_only"
    server = [p for p in files if not any(p.startswith(x) for x in settings["server_exclude"])]
    part = Slice(slice_id="all", name="all", files=[SliceFile(path=p) for p in server])
    record["errors"].pop()
    return _ask(case, part, snapshot, gateway, record, claims)


def _run_c(snapshot, gateway, config, slices_file, record, claims) -> bool:
    slices = load_slices(Path(slices_file), snapshot)
    by_id = {s.slice_id: s for s in slices}
    record["truncated"] = [t for s in slices for t in s.truncated]
    for case in build_cases(slices, [], config.budget, lenses=load_lenses()):
        _ask(case, by_id[case.slice_id], snapshot, gateway, record, claims)
    return True


def _run_d(snapshot, gateway, config, slices_file, rules_file, record, claims) -> bool:
    """C에 승인된 보안 규칙을 더한다. 근거 확인과 재검토는 하지 않는다."""
    slices = load_slices(Path(slices_file), snapshot)
    by_id = {s.slice_id: s for s in slices}
    rules = {r.rule_id: r for r in load_rules(Path(rules_file))}
    for case in build_cases(slices, list(rules.values()), config.budget, lenses=load_lenses()):
        rule = rules.get(case.subject_id)
        requirement = f"{rule.doc_ref}: {rule.requirement_quote}" if rule and rule.requirement_quote else None
        _ask(case, by_id[case.slice_id], snapshot, gateway, record, claims, requirement)
    return True


def _run_e(root, run_dir, config, slices_file, rules_file, design, record, claims) -> bool:
    """전체 구조. 근거 확인과 재검토를 통과해 남은 문제만 결과로 낸다."""
    result = run_scan(root, design=list(design), out=run_dir, config=config, slices_file=Path(slices_file),
                      rules=load_rules(Path(rules_file)))
    record["verdicts"] = dict(Counter(v.state.value for v in result.verdicts))
    record["errors"] += [c.reason for c in result.ledger if c.state == LedgerState.not_seen]
    claims.extend(v.evidence for v in result.verdicts if v.state == VerdictState.missing_suspected and v.evidence)
    return True


def _totals(run_dir: Path) -> dict:
    rows = [json.loads(line) for line in (run_dir / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    sent = [r for r in rows if r["input_tokens"] or r["output_tokens"]]
    return {
        "calls": len(sent),
        "input_tokens": sum(r["input_tokens"] for r in rows),
        "output_tokens": sum(r["output_tokens"] for r in rows),
        "seconds": round(sum(r["seconds"] for r in rows), 3),
        "models": sorted({r["model"] for r in rows if r["model"]}),
    }


def run_condition(
    condition, target, out, *, config, conditions, repeat, slices_file=None, rules_file=None, design=()
) -> dict:
    """한 회차를 돌려 r<N>.sarif와 r<N>.run.json을 쓴다. 호출이 없었으면 SARIF를 쓰지 않아 0건으로 채점되지 않는다."""
    root = open_target(Path(target), Path(out) / "_target")
    out = Path(out)
    run_dir = out / f"r{repeat}.d"
    run_dir.mkdir(parents=True, exist_ok=True)
    snapshot = scan_scope(root)
    gateway = LlmGateway(config, run_dir)
    record: dict = {"condition": condition, "repeat": repeat, "status": "ok", "input": "all", "errors": [],
                    "dispositions": [], "note": "잠정: 사람 검토 전"}
    claims: list = []
    if condition == "B":
        called = _run_b(snapshot, gateway, conditions["B"], record, claims)
    elif condition == "C":
        called = _run_c(snapshot, gateway, config, slices_file, record, claims)
    elif condition == "D":
        called = _run_d(snapshot, gateway, config, slices_file, rules_file, record, claims)
    else:
        called = _run_e(root, run_dir, config, slices_file, rules_file, design, record, claims)

    record["claims"] = len(claims)
    record |= _totals(run_dir)
    if record["errors"] and record["status"] == "ok":
        record["status"] = "partial" if record["calls"] else "failed"
    if called and (record["calls"] or record["status"] == "ok"):
        sarif = to_sarif(claims, tool_name=f"{condition}-r{repeat}")
        (out / f"r{repeat}.sarif").write_text(json.dumps(sarif, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / f"r{repeat}.run.json").write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", choices=["B", "C", "D", "E"], required=True)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--experiment", default="bc")
    parser.add_argument("--target", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--slices", type=Path, default=ROOT / "eval" / "slices" / "dev.yml")
    parser.add_argument("--rules", type=Path, default=ROOT / "eval" / "rules" / "dev.yml")
    parser.add_argument("--design", type=Path, action="append")
    args = parser.parse_args()

    target = args.target or BENCH / "artifacts" / args.variant / "scan-input"
    conditions = yaml.safe_load((ROOT / "eval" / "conditions.yml").read_text(encoding="utf-8"))
    config = load_config(args.config)
    out = ROOT / "eval" / "runs" / args.experiment / args.condition / args.variant
    design = args.design or sorted((BENCH / "designs" / "dev").glob("*.md"))
    for n in range(1, args.repeat + 1):
        record = run_condition(args.condition, target, out, config=config, conditions=conditions, repeat=n,
                               slices_file=args.slices, rules_file=args.rules, design=design)
        print(f"{args.condition} {args.variant} r{n}: {record['status']} 주장 {record['claims']} "
              f"토큰 {record['input_tokens']}+{record['output_tokens']} {record['seconds']}초")


if __name__ == "__main__":
    main()
