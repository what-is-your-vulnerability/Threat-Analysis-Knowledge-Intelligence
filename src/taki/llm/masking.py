"""외부로 보내기 전에 비밀값과 개인정보를 같은 길이의 X로 가린다. 줄 번호와 연산자는 그대로 남는다."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath

import yaml

from taki.config import RULES_DIR


@dataclass
class MaskResult:
    text: str
    replacements: int


CONFIG_SUFFIXES = {".yml", ".yaml", ".properties", ".env", ".conf", ".ini", ".cfg"}


@lru_cache(maxsize=2)
def _patterns(config_only: bool = False) -> list[tuple[str, re.Pattern, int]]:
    rows = yaml.safe_load((RULES_DIR / "secrets.yml").read_text(encoding="utf-8"))
    return [(r["name"], re.compile(r["pattern"]), r.get("group", 0)) for r in rows
            if r.get("config_only", False) == config_only]


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


def _mask(text: str, patterns) -> MaskResult:
    count = 0
    for _, pattern, group in patterns:
        spans = [m.span(group) for m in pattern.finditer(text) if not _is_masked(m.group(group))]
        for start, end in reversed(spans):
            text = text[:start] + re.sub(r"[^\n]", "X", text[start:end]) + text[end:]
        count += len(spans)
    return MaskResult(text, count)


def mask_text(text: str) -> MaskResult:
    return _mask(text, _patterns())


def mask_file_text(path: str, text: str) -> str:
    """설정 파일이면 따옴표 없는 비밀값도 가린다. 파일을 읽어 밖으로 내보내는 곳에서 부른다."""
    name = PurePosixPath(path).name.lower()
    if PurePosixPath(name).suffix in CONFIG_SUFFIXES or name.startswith(".env"):
        return _mask(text, _patterns(config_only=True)).text
    return text
