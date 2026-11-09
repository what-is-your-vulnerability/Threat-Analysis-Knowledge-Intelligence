"""폴더·ZIP 입력을 분석 폴더로 바꾼다. Agent가 정답·저작 자료를 읽지 못하게 막는다."""

from __future__ import annotations

import zipfile
from pathlib import Path

FORBIDDEN_NAMES = {"ground-truth-private", "authoring", "test-private"}
FORBIDDEN_CHILD_NAMES = FORBIDDEN_NAMES | {"work"}


class ForbiddenPathError(ValueError):
    pass


def check_allowed(path: Path) -> None:
    parts = path.parts
    if FORBIDDEN_NAMES.intersection(parts):
        raise ForbiddenPathError(f"접근 금지 경로: {path}")
    # `work`는 흔한 폴더 이름이라 벤치마크 아래일 때만 막는다. 대상 안의 work/는 scan_scope가 막는다.
    if "benchmarks" in parts and "work" in parts[parts.index("benchmarks") :]:
        raise ForbiddenPathError(f"접근 금지 경로: {path}")


def _extract_zip(archive: Path, dest: Path) -> Path:
    # shortcut: 압축 해제 크기 제한 없음, 외부 업로드를 받게 되면 추가한다.
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            if not (root / name).resolve().is_relative_to(root):
                raise ForbiddenPathError(f"압축 파일 항목이 대상 밖을 가리킴: {name}")
        z.extractall(root)
    return root


def open_target(path: Path, workdir: Path) -> Path:
    resolved = Path(path).resolve()
    check_allowed(resolved)
    if resolved.is_file() and zipfile.is_zipfile(resolved):
        return _extract_zip(resolved, Path(workdir) / resolved.stem)
    return resolved
