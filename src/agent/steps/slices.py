"""기능 묶음을 만들고, LLM에게 보여 줄 형태로 바꾼다. 묶음은 손으로 쓰거나 진입점에서 자동으로 만든다."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agent.adapters.lang.java_index import JavaClass, JavaIndex, JavaMethod
from agent.adapters.lang.mybatis import MapperIndex, MapperStatement
from agent.adapters.lang.treesitter import walk
from agent.llm.masking import mask_file_text
from agent.schemas.models import (
    Capability,
    Certainty,
    EntryPoint,
    Fact,
    Flow,
    Hop,
    Relation,
    Role,
    Slice,
    SliceFile,
    Snapshot,
)

GREP_CONTEXT = 15
MAX_METHODS = 60
VERSION_PREFIX_RE = re.compile(r"^(api|rest|v\d+)$", re.IGNORECASE)
STATE_FIELD_RE = re.compile(r"status|state|role|locked|deleted", re.IGNORECASE)
ROUTE_IN_TEXT_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s`]*)")
HEADING_RE = re.compile(r"^#+\s+(\d+(?:\.\d+)*)")
PARAM_RE = re.compile(r"\{[^}]*\}|:[A-Za-z_]\w*")
MAX_USAGE_POSITIONS = 8
# 줄 수 한도를 넘으면 숫자가 큰 것부터 뺀다.
PRIORITY_HANDLER, PRIORITY_GUARD, PRIORITY_CALLEE, PRIORITY_MAPPER, PRIORITY_DTO, PRIORITY_VIEW = range(6)


def flow_id(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _read_lines(snapshot: Snapshot, path: str) -> list[str]:
    text = (snapshot.root / path).read_text(encoding="utf-8", errors="replace")
    return mask_file_text(path, text).split("\n")


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


def render_slice(slice_: Slice, snapshot: Snapshot, alerts: Sequence[Fact] = ()) -> str:
    parts: list[str] = []
    if alerts:
        parts.append("=== 정적분석 경고(도구 결과, 코드로 확인 필요) ===")
        parts += [f"{a.tool} {a.detail.get('rule')} {a.detail.get('cwe')} {a.file}:{a.line} {a.detail.get('message', '')}"
                  for a in alerts]
    if slice_.sibling_table:
        parts.append("=== 이 묶음의 API와 확인된 검사 ===")
        parts += [f"{row['method']} {row['path']} | 검사: {', '.join(row['guards']) or '없음'}"
                  for row in slice_.sibling_table]
    paths = [(f.flow_id, f.hops) for f in slice_.flows if f.hops]
    if paths:
        parts.append("=== 호출 경로 ===")
        parts += [f"{name}: " + " -> ".join(f"{h.file}:{h.start}" for h in hops) for name, hops in paths]
    if slice_.related:
        parts.append("=== 참고: 코드가 포함되지 않은 관련 위치 ===")
        parts += slice_.related
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
            # 검사 목록을 적지 않은 흐름은 "검사 없음"으로 보이지 않게 표를 만들지 않는다.
            sibling_table=[{"method": f.method, "path": f.path, "guards": f.guards} for f in flows]
            if all("guards" in f for f in row.get("flows", [])) else [],
            requirement_refs=[row["requirement"]] if row.get("requirement") else [],
            truncated=truncated, capability=Capability.partial if truncated else Capability.supported,
        )
        slice_.code_hash = hashlib.sha256(render_slice(slice_, snapshot).encode()).hexdigest()
        slices.append(slice_)
    return slices


@dataclass
class _Reach:
    """진입점 하나에서 호출을 따라가 닿은 코드."""

    entry: EntryPoint
    methods: list[JavaMethod] = field(default_factory=list)
    statements: list[MapperStatement] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    symbols: dict[str, str] = field(default_factory=dict)


def _line_of(snapshot: Snapshot, path: str, line: int) -> str:
    return _read_lines(snapshot, path)[line - 1].strip()


def _method_hop(snapshot, method: JavaMethod, role: Role, certainty: Certainty) -> Hop:
    line = method.node.child_by_field_name("name").start_point[0] + 1
    # end는 메서드 끝이다. 구현 근거가 이 호출 경로 안에 있는지 확인할 때 범위로 쓴다.
    return Hop(file=method.file, start=line, end=method.end, quote=_line_of(snapshot, method.file, line), role=role,
               relation=Relation.calls, certainty=certainty)


def _follow_calls(entry: EntryPoint, snapshot, index: JavaIndex, mappers: MapperIndex) -> _Reach:
    reach = _Reach(entry)
    start = index.method(entry.handler_symbol)
    if start is None:
        reach.unresolved.append(f"핸들러를 찾지 못함: {entry.handler_symbol}")
        return reach
    queue = [(start, Role.entrypoint, Certainty.code_read)]
    seen = {start.symbol}
    while queue:
        if len(reach.methods) >= MAX_METHODS:
            reach.unresolved.append("호출 수 한도 초과")
            break
        method, role, certainty = queue.pop(0)
        reach.methods.append(method)
        hop = _method_hop(snapshot, method, role, certainty)
        reach.hops.append(hop)
        reach.symbols[f"{hop.file}:{hop.start}"] = method.symbol
        owner = method.owner
        if owner.kind == "interface":
            statement = mappers.get((f"{owner.package}.{owner.name}" if owner.package else owner.name, method.name))
            if statement:
                reach.statements.append(statement)
                reach.hops.append(Hop(file=statement.file, start=statement.start, end=statement.end,
                                      quote=_line_of(snapshot, statement.file, statement.start), role=Role.sink,
                                      relation=Relation.calls))
            elif "Mapper" in {a.name for a in owner.annotations} and not _has_sql_annotation(method):
                reach.unresolved.append(f"{method.symbol} (매퍼 문장 없음)")
            continue
        reach.unresolved += index.unresolved_calls(method.symbol)
        for call in index.calls_from(method.symbol):
            result = index.resolve_call(method.symbol, call)
            for target in result.targets:
                callee = index.method(target)
                if callee is not None and callee.symbol not in seen:
                    seen.add(callee.symbol)
                    queue.append((callee, Role.propagation, result.certainty))
    reach.unresolved = list(dict.fromkeys(reach.unresolved))
    return reach


def _has_sql_annotation(method: JavaMethod) -> bool:
    return bool({a.name for a in method.annotations} & {"Select", "Insert", "Update", "Delete"})


class _FileSet:
    def __init__(self, snapshot: Snapshot):
        self.lines = {f.path: f.lines for f in snapshot.files}
        self.ranges: dict[str, list[tuple[int, int]] | None] = {}
        self.priority: dict[str, int] = {}

    def add(self, path: str, start: int | None = None, end: int | None = None, *, priority: int) -> None:
        if path not in self.lines:
            return
        self.priority[path] = min(priority, self.priority.get(path, priority))
        if start is None:
            self.ranges[path] = None
        elif self.ranges.get(path, []) is not None:
            self.ranges.setdefault(path, []).append((start, end))

    def merged(self, path: str) -> list[tuple[int, int]] | None:
        ranges = self.ranges[path]
        if ranges is None:
            return None
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        return merged

    def count(self, path: str) -> int:
        ranges = self.merged(path)
        return self.lines[path] if ranges is None else sum(b - a + 1 for a, b in ranges)

    def total(self) -> int:
        return sum(self.count(p) for p in self.ranges)


def _class_outline(files: _FileSet, cls: JavaClass, priority: int) -> None:
    """클래스 선언과 필드까지만 넣는다. 메서드 본문은 호출된 것만 따로 넣는다."""
    body = cls.node.child_by_field_name("body")
    header_end = body.start_point[0] + 1 if body is not None else cls.end
    files.add(cls.file, cls.start, header_end, priority=priority)
    for node in cls.field_nodes:
        files.add(cls.file, node.start_point[0] + 1, node.end_point[0] + 1, priority=priority)


def _signature_types(method: JavaMethod) -> set[str]:
    names = set()
    for part in ("type", "parameters"):
        node = method.node.child_by_field_name(part)
        if node is not None:
            names |= {n.text.decode() for n in walk(node) if n.type == "type_identifier"}
    return names


def _returned_views(method: JavaMethod) -> list[str]:
    body = method.node.child_by_field_name("body")
    views = []
    for node in walk(body) if body is not None else []:
        if node.type == "return_statement":
            views += ["".join(c.text.decode() for c in child.children if c.type == "string_fragment")
                      for child in node.children if child.type == "string_literal"]
    return views


def _collect_files(reaches: list[_Reach], snapshot, index: JavaIndex) -> _FileSet:
    files = _FileSet(snapshot)
    for reach in reaches:
        for guard in reach.entry.middleware:
            if guard.scope in ("global", "prefix"):
                target = index.cls(guard.symbol)
                files.add(target.file if target else guard.file or "", priority=PRIORITY_GUARD)
                if guard.file:
                    files.add(guard.file, priority=PRIORITY_GUARD)
        for position, method in enumerate(reach.methods):
            priority = PRIORITY_HANDLER if position == 0 else PRIORITY_CALLEE
            owner = method.owner
            _class_outline(files, owner, priority)
            files.add(method.file, method.start, method.end, priority=priority)
            for name in _signature_types(method):
                dto = index.cls(name)
                if dto is not None:
                    files.add(dto.file, dto.start, dto.end, priority=PRIORITY_DTO)
        for statement in reach.statements:
            files.add(statement.file, statement.start, statement.end, priority=PRIORITY_MAPPER)
            for path, start, end in statement.fragments:
                files.add(path, start, end, priority=PRIORITY_MAPPER)
        if reach.methods:
            for view in _returned_views(reach.methods[0]):
                suffix = f"templates/{view}.html"
                for path in files.lines:
                    if path.endswith(suffix):
                        files.add(path, priority=PRIORITY_VIEW)
    return files


def _normalize_route(path: str) -> str:
    return PARAM_RE.sub("{}", path).rstrip("/")


def _requirement_map(design_docs) -> dict[tuple[str, str], str]:
    found = {}
    for doc in design_docs:
        section = None
        for line in Path(doc).read_text(encoding="utf-8", errors="replace").splitlines():
            heading = HEADING_RE.match(line)
            if heading:
                section = heading.group(1)
            for method, route in ROUTE_IN_TEXT_RE.findall(line):
                found.setdefault((method, _normalize_route(route)), f"{Path(doc).name}#{section}")
    return found


def _segments(path: str) -> list[str]:
    parts = [p for p in path.split("/") if p]
    while parts and VERSION_PREFIX_RE.match(parts[0]):
        parts.pop(0)
    return [p for p in parts if not p.startswith("{")]


def _sibling_table(reaches: list[_Reach], requirements: dict) -> list[dict]:
    if len(reaches) < 2:
        return []
    rows = []
    for reach in sorted(reaches, key=lambda r: (r.entry.method, r.entry.path_template)):
        row = {"method": reach.entry.method, "path": reach.entry.path_template, "guards": reach.entry.effective_guards,
               "handler": reach.entry.handler_symbol}
        ref = requirements.get((reach.entry.method, _normalize_route(reach.entry.path_template)))
        if ref:
            row["requirement"] = ref
        rows.append(row)
    return rows


def _related(reaches: list[_Reach], others: list[_Reach], index: JavaIndex, table_rows: list[dict]) -> list[str]:
    notes = [] if table_rows else ["같은 구간에 비교할 API 없음"]
    tables = {t for r in reaches for s in r.statements for t in s.tables}
    for table in sorted(tables):
        writers = sorted({
            f"{o.entry.method} {o.entry.path_template} ({o.entry.handler_symbol})"
            for o in others for s in o.statements if s.kind != "select" and table in s.tables
        })
        if writers:
            notes.append(f"{table}에 쓰는 다른 API: " + ", ".join(writers))
    owners = {m.class_name for r in reaches for m in r.methods}
    for fact in index.shared_state():
        if fact.symbol.split(".")[0] in owners:
            notes.append(f"공유 상태({fact.kind}): {fact.symbol} @ {fact.file}:{fact.line}")
    seen_fields = set()
    for owner in sorted(owners):
        cls = index.cls(owner)
        for name in cls.fields if cls else []:
            if STATE_FIELD_RE.search(name) and name not in seen_fields:
                seen_fields.add(name)
                places = [f"{u.file}:{u.line}" for u in index.field_usages(name)][:MAX_USAGE_POSITIONS]
                notes.append(f"상태 필드 {name} 사용처: " + ", ".join(places))
    return notes


def _trim(files: _FileSet, max_lines: int) -> tuple[list[str], bool]:
    """한도를 넘으면 우선순위가 낮은 파일부터 빼고 뺀 파일 경로를 돌려준다."""
    dropped = []
    guard_dropped = False
    for path in sorted(files.ranges, key=lambda p: -files.priority[p]):
        if files.total() <= max_lines or files.priority[path] == PRIORITY_HANDLER:
            continue
        guard_dropped = guard_dropped or files.priority[path] == PRIORITY_GUARD
        dropped.append(path)
        del files.ranges[path]
    return dropped, guard_dropped


def _reach_files(reach: _Reach) -> set[str]:
    return ({m.file for m in reach.methods} | {s.file for s in reach.statements}
            | {path for s in reach.statements for path, _, _ in s.fragments})


def _guard_files(entry: EntryPoint, index: JavaIndex) -> list[str]:
    files = set()
    for guard in entry.middleware:
        if guard.scope in ("global", "prefix"):
            files.add(guard.file)
            target = index.cls(guard.symbol)
            files.add(target.file if target else None)
    return sorted(f for f in files if f)


def locate_handlers(slices: list[Slice], index: JavaIndex) -> None:
    """손 작성 묶음의 흐름에 핸들러 위치를 채운다. 찾지 못하면 비워 두어 구현 확인을 내지 않게 한다."""
    for slice_ in slices:
        for flow in slice_.flows:
            method = index.method(flow.handler_symbol or "")
            if method is not None and flow.handler_file is None:
                flow.handler_file, flow.handler_start, flow.handler_end = method.file, method.start, method.end


def _make_slice(name, reaches, table, requirements, snapshot, index, others, max_lines) -> Slice:
    files = _collect_files(reaches, snapshot, index)
    dropped, guard_dropped = _trim(files, max_lines)
    truncated = [f"한도를 넘어 뺌: {path}" for path in dropped]
    flows = [
        Flow(flow_id=flow_id(r.entry.method, r.entry.path_template), method=r.entry.method, path=r.entry.path_template,
             handler_symbol=r.entry.handler_symbol, hops=r.hops, symbols=r.symbols, guards=r.entry.effective_guards,
             middleware_complete=r.entry.middleware_complete and not guard_dropped,
             # 한도로 뺀 코드를 지나는 흐름은 LLM이 다 보지 못했으므로 "없다" 주장을 입증할 수 없다.
             unresolved=[*r.unresolved, *([r.entry.unresolved_reason] if r.entry.unresolved_reason else []),
                         *(f"한도로 뺀 코드: {path}" for path in dropped if path in _reach_files(r))],
             handler_file=r.entry.handler_file, handler_start=r.entry.handler_start, handler_end=r.entry.handler_end,
             guard_files=_guard_files(r.entry, index))
        for r in reaches
    ]
    slice_ = Slice(
        slice_id=name, name=name, flows=flows, files=[SliceFile(path=p, ranges=files.merged(p)) for p in sorted(files.ranges)],
        sibling_table=table, requirement_refs=sorted({row["requirement"] for row in table if "requirement" in row}),
        related=_related(reaches, others, index, table), truncated=truncated,
        capability=Capability.partial if truncated else Capability.supported,
    )
    slice_.code_hash = hashlib.sha256(render_slice(slice_, snapshot).encode()).hexdigest()
    return slice_


def _split(name, reaches, depth, table, requirements, snapshot, index, all_reaches, max_lines) -> list[Slice]:
    others = [r for r in all_reaches if r not in reaches]
    files = _collect_files(reaches, snapshot, index)
    if files.total() <= max_lines or len(reaches) == 1:
        return [_make_slice(name, reaches, table, requirements, snapshot, index, others, max_lines)]
    groups: dict[str, list[_Reach]] = {}
    for reach in reaches:
        parts = _segments(reach.entry.path_template)
        key = parts[depth] if depth < len(parts) else ""
        groups.setdefault(key, []).append(reach)
    if len(groups) == 1:
        depth_exhausted = depth > 8
        if not depth_exhausted:
            return _split(name, reaches, depth + 1, table, requirements, snapshot, index, all_reaches, max_lines)
        groups = {str(i): [r] for i, r in enumerate(reaches)}
    slices = []
    for key, group in groups.items():
        child = f"{name}/{key}" if key else name
        slices += _split(child, group, depth + 1, table, requirements, snapshot, index, all_reaches, max_lines)
    return slices


def _apply_overrides(slices: list[Slice], path: Path, snapshot: Snapshot) -> None:
    listed = {f.path for f in snapshot.files}
    for row in yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []:
        for slice_ in slices:
            if slice_.name != row["name"]:
                continue
            removed = set(row.get("remove_files", []))
            slice_.files = [f for f in slice_.files if f.path not in removed]
            slice_.files += [SliceFile(path=p) for p in row.get("add_files", []) if p in listed]
            slice_.code_hash = hashlib.sha256(render_slice(slice_, snapshot).encode()).hexdigest()


def build_slices(snapshot, entrypoints, index, mappers, *, design_docs=(), max_lines=1500, overrides=None) -> list[Slice]:
    requirements = _requirement_map(design_docs)
    reaches = [_follow_calls(e, snapshot, index, mappers) for e in entrypoints]
    groups: dict[str, list[_Reach]] = {}
    for reach in reaches:
        parts = _segments(reach.entry.path_template)
        groups.setdefault(parts[0] if parts else "root", []).append(reach)
    slices = []
    for name, group in sorted(groups.items()):
        table = _sibling_table(group, requirements)  # 나눠도 형제를 비교할 수 있게 나누기 전에 만든다.
        slices += _split(name, group, 1, table, requirements, snapshot, index, reaches, max_lines)
    if overrides:
        _apply_overrides(slices, overrides, snapshot)
    return slices


def fallback_slices(snapshot: Snapshot, max_lines: int = 1500) -> list[Slice]:
    """알아보는 프레임워크가 없을 때 폴더 단위로 나눈다. 진입점을 모르므로 항상 partial이다."""
    by_folder: dict[str, list] = {}
    for entry in snapshot.files:
        by_folder.setdefault(str(Path(entry.path).parent), []).append(entry)
    slices = []
    for folder, entries in sorted(by_folder.items()):
        chunk: list = []
        size = 0
        part = 1
        for entry in [*entries, None]:
            if entry is None or (chunk and size + entry.lines > max_lines):
                name = f"{folder}#{part}"
                slice_ = Slice(slice_id=name, name=name, files=[SliceFile(path=e.path) for e in chunk],
                               capability=Capability.partial)
                slice_.code_hash = hashlib.sha256(render_slice(slice_, snapshot).encode()).hexdigest()
                slices.append(slice_)
                chunk, size, part = [], 0, part + 1
            if entry is not None:
                chunk.append(entry)
                size += entry.lines
    return slices
