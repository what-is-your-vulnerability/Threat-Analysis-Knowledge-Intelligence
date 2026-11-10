"""보안 규칙이 없어도 묶음마다 묻는 고정 질문."""

from __future__ import annotations

import yaml
from pydantic import BaseModel

from agent.config import RULES_DIR


class Lens(BaseModel):
    lens_id: str
    category: int
    question: str


def load_lenses() -> list[Lens]:
    rows = yaml.safe_load((RULES_DIR / "lenses.yml").read_text(encoding="utf-8"))
    return [Lens.model_validate(r) for r in rows]


def render_questions(lenses) -> str:
    lines = [f"{x.lens_id} (탐지 범위 {x.category}): {x.question}" for x in lenses]
    return "이 코드 묶음에 대해 다음 질문에 lens_id별로 답하라.\n" + "\n".join(lines)
