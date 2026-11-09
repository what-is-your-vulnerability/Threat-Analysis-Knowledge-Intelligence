from pathlib import Path

import pytest

from agent.adapters.repo.local import ForbiddenPathError
from eval.run import run_condition

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {ROOT / "src/agent/adapters/repo/local.py"}


def test_package_never_references_ground_truth():
    sources = [*(ROOT / "src/agent").rglob("*.py"), ROOT / "eval/run.py"]
    assert [p for p in sources if "ground-truth-private" in p.read_text(encoding="utf-8") and p not in ALLOWED] == []


def test_run_rejects_ground_truth_path(tmp_path):
    target = tmp_path / "ground-truth-private"
    target.mkdir()
    with pytest.raises(ForbiddenPathError):
        run_condition("C", target, tmp_path / "out", config=None, conditions={}, repeat=1)
