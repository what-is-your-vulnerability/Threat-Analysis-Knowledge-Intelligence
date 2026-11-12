"""분석 대상 파일 목록과 못 읽은 파일 목록을 만든다."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from taki.adapters.repo.local import FORBIDDEN_CHILD_NAMES
from taki.schemas.models import Capability, FileEntry, NotRead, Snapshot

LANGUAGES = {
    ".java": "java",
    ".xml": "xml",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".c": "c",
    ".h": "c",
    ".pc": "proc",
    ".py": "python",
    ".html": "html",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".properties": "properties",
    ".sql": "sql",
}
EXCLUDED_DIRS = {".git", "node_modules", "target", "build", "dist"}


def _read_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    # 고정 인자 목록, 셸 없음. root는 경로 인자 하나로만 넘긴다
    r = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def _is_result_folder(path: Path, exclude) -> bool:
    # 이 도구가 대상 폴더 안에 쓴 결과는 다음 검사의 분석 대상이나 근거가 되면 안 된다.
    return path.resolve() in exclude or ((path / "report.json").exists() and (path / "ledger.json").exists())


def _walk(directory: Path, root: Path, files: list[FileEntry], not_read: list[NotRead], exclude=()) -> None:
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        rel = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            not_read.append(NotRead(path=rel, reason="심볼릭 링크"))
        elif entry.is_dir() and _is_result_folder(entry, exclude):
            not_read.append(NotRead(path=rel, reason="검사 결과 폴더"))
        elif entry.is_dir():
            if entry.name in FORBIDDEN_CHILD_NAMES:
                not_read.append(NotRead(path=rel, reason="금지 폴더"))
            elif entry.name in EXCLUDED_DIRS:
                not_read.append(NotRead(path=rel, reason="제외 폴더"))
            else:
                _walk(entry, root, files, not_read, exclude)
        else:
            language = LANGUAGES.get(entry.suffix.lower())
            if language is None:
                not_read.append(NotRead(path=rel, reason="지원하지 않는 확장자"))
                continue
            data = entry.read_bytes()
            if b"\x00" in data:
                not_read.append(NotRead(path=rel, reason="바이너리"))
                continue
            lines = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
            files.append(FileEntry(path=rel, sha256=hashlib.sha256(data).hexdigest(), language=language, lines=lines))


def scan_scope(root: Path, exclude=()) -> Snapshot:
    root = Path(root).resolve()
    files: list[FileEntry] = []
    not_read: list[NotRead] = []
    _walk(root, root, files, not_read, tuple(exclude))
    listing = "\n".join(sorted(f"{f.path}\x00{f.sha256}" for f in files))
    return Snapshot(
        root=root,
        commit=_read_commit(root),
        manifest_hash=hashlib.sha256(listing.encode()).hexdigest(),
        files=files,
        not_read=not_read,
        status=Capability.supported if files else Capability.failed,
    )
