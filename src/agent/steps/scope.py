"""분석 대상 파일 목록과 못 읽은 파일 목록을 만든다."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from agent.adapters.repo.local import FORBIDDEN_CHILD_NAMES
from agent.schemas.models import Capability, FileEntry, NotRead, Snapshot

LANGUAGES = {
    ".java": "java", ".xml": "xml", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".c": "c", ".h": "c", ".pc": "proc",
    ".py": "python", ".html": "html", ".yml": "yaml", ".yaml": "yaml", ".properties": "properties", ".sql": "sql",
}
EXCLUDED_DIRS = {".git", "node_modules", "target", "build", "dist"}


def _read_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def _walk(directory: Path, root: Path, files: list[FileEntry], not_read: list[NotRead]) -> None:
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        rel = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            not_read.append(NotRead(path=rel, reason="심볼릭 링크"))
        elif entry.is_dir():
            if entry.name in FORBIDDEN_CHILD_NAMES:
                not_read.append(NotRead(path=rel, reason="금지 폴더"))
            elif entry.name in EXCLUDED_DIRS:
                not_read.append(NotRead(path=rel, reason="제외 폴더"))
            else:
                _walk(entry, root, files, not_read)
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


def scan_scope(root: Path) -> Snapshot:
    root = Path(root).resolve()
    files: list[FileEntry] = []
    not_read: list[NotRead] = []
    _walk(root, root, files, not_read)
    listing = "\n".join(sorted(f"{f.path}\x00{f.sha256}" for f in files))
    return Snapshot(
        root=root,
        commit=_read_commit(root),
        manifest_hash=hashlib.sha256(listing.encode()).hexdigest(),
        files=files,
        not_read=not_read,
        status=Capability.supported if files else Capability.failed,
    )
