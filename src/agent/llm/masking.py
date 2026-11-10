"""외부로 보내기 전에 비밀값과 개인정보를 같은 길이의 X로 가린다. 줄 번호와 연산자는 그대로 남는다."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

import yaml

from agent.config import RULES_DIR


@dataclass
class MaskResult:
    text: str
    replacements: int


@lru_cache(maxsize=1)
def _patterns() -> list[tuple[str, re.Pattern, int]]:
    rows = yaml.safe_load((RULES_DIR / "secrets.yml").read_text(encoding="utf-8"))
    return [(r["name"], re.compile(r["pattern"]), r.get("group", 0)) for r in rows]


def _is_masked(value: str) -> bool:
    return not value.replace("X", "").replace("\n", "")


def find_secrets(text: str) -> list[str]:
    """아직 가려지지 않은 값이 있는 패턴 이름을 돌려준다."""
    return [
        name
        for name, pattern, group in _patterns()
        for m in pattern.finditer(text)
        if not _is_masked(m.group(group))
    ]


def mask_text(text: str) -> MaskResult:
    count = 0
    for _, pattern, group in _patterns():
        spans = [m.span(group) for m in pattern.finditer(text) if not _is_masked(m.group(group))]
        for start, end in reversed(spans):
            text = text[:start] + re.sub(r"[^\n]", "X", text[start:end]) + text[end:]
        count += len(spans)
    return MaskResult(text, count)
