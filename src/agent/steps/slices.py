"""기능 묶음을 읽고, LLM에게 보여 줄 형태로 만든다."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

from agent.schemas.models import Capability, Flow, Slice, SliceFile, Snapshot

GREP_CONTEXT = 15


def flow_id(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _read_lines(snapshot: Snapshot, path: str) -> list[str]:
    return (snapshot.root / path).read_text(encoding="utf-8", errors="replace").split("\n")


def _grep_ranges(lines: list[str], pattern: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for number, line in enumerate(lines, start=1):
        if not re.search(pattern, line):
            continue
        start, end = max(1, number - GREP_CONTEXT), min(len(lines), number + GREP_CONTEXT)
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    return ranges


def render_slice(slice_: Slice, snapshot: Snapshot) -> str:
    parts: list[str] = []
    if slice_.sibling_table:
        parts.append("=== 이 묶음의 API와 확인된 검사 ===")
        parts += [f"{row['method']} {row['path']} | 검사: {', '.join(row['guards']) or '없음'}"
                  for row in slice_.sibling_table]
    for file in slice_.files:
        lines = _read_lines(snapshot, file.path)
        if lines and lines[-1] == "":
            lines = lines[:-1]
        parts.append(f"=== FILE {file.path} ===")
        for start, end in file.ranges or [(1, len(lines))]:
            parts += [f"{n:>5}| {lines[n - 1]}" for n in range(start, min(end, len(lines)) + 1)]
    return "\n".join(parts)


def load_slices(path: Path, snapshot: Snapshot) -> list[Slice]:
    """손으로 쓴 묶음 파일을 읽는다. 없는 파일은 버리지 않고 truncated에 남겨 못 본 범위로 알린다."""
    listed = {f.path for f in snapshot.files}
    slices = []
    for row in yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []:
        files: list[SliceFile] = []
        truncated: list[str] = []
        for item in row.get("files", []):
            if item["path"] not in listed:
                truncated.append(f"파일 없음: {item['path']}")
                continue
            ranges = None
            if item.get("grep"):
                ranges = _grep_ranges(_read_lines(snapshot, item["path"]), item["grep"])
                if not ranges:
                    truncated.append(f"일치하는 줄 없음: {item['path']} ({item['grep']})")
                    continue
            files.append(SliceFile(path=item["path"], ranges=ranges))
        flows = [
            Flow(flow_id=flow_id(f["method"], f["path"]), method=f["method"].upper(), path=f["path"],
                 handler_symbol=f.get("handler_symbol"), guards=f.get("guards", []),
                 middleware_complete=f.get("middleware_complete", False), unresolved=f.get("unresolved", []))
            for f in row.get("flows", [])
        ]
        slice_ = Slice(
            slice_id=row["name"], name=row["name"], flows=flows, files=files,
            sibling_table=[{"method": f.method, "path": f.path, "guards": f.guards} for f in flows],
            requirement_refs=[row["requirement"]] if row.get("requirement") else [],
            truncated=truncated, capability=Capability.partial if truncated else Capability.supported,
        )
        slice_.code_hash = hashlib.sha256(render_slice(slice_, snapshot).encode()).hexdigest()
        slices.append(slice_)
    return slices
