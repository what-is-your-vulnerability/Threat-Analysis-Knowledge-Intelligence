"""MyBatis 매퍼 XML을 읽어 SQL 문장, 테이블, 파라미터를 뽑는다."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.parsers import expat

from taki.schemas.models import Snapshot

STATEMENT_TAGS = {"select", "insert", "update", "delete"}
TABLE_RE = re.compile(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+([A-Za-z_][\w.$]*)", re.IGNORECASE)
HASH_RE = re.compile(r"#\{\s*([\w.]+)")
DOLLAR_RE = re.compile(r"\$\{\s*([\w.]+)")
NOT_TABLES = {"DUAL"}


@dataclass
class MapperStatement:
    namespace: str
    id: str
    kind: str
    file: str
    start: int
    end: int
    sql: str = ""
    tables: set[str] = field(default_factory=set)
    dollar_params: set[str] = field(default_factory=set)
    hash_params: set[str] = field(default_factory=set)
    fragments: list[tuple[str, int, int]] = field(default_factory=list)  # 펼친 <sql>의 (파일, 시작, 끝)


class MapperIndex(dict):
    """(namespace, id) -> MapperStatement. 읽지 못한 파일과 풀지 못한 include는 errors에 남는다."""

    def __init__(self):
        super().__init__()
        self.errors: list[str] = []


@dataclass
class _Block:
    kind: str
    id: str
    start: int
    end: int = 0
    file: str = ""
    parts: list = field(default_factory=list)  # 글자 또는 ("include", refid)


def _parse_file(text: str) -> tuple[str | None, list[_Block]]:
    namespace: list[str | None] = [None]
    blocks: list[_Block] = []
    stack: list[_Block] = []
    parser = expat.ParserCreate()

    def on_start(tag, attrs):
        if tag == "mapper":
            namespace[0] = attrs.get("namespace")
        elif namespace[0] and tag in STATEMENT_TAGS | {"sql"} and "id" in attrs and not stack:
            stack.append(_Block(tag, attrs["id"], parser.CurrentLineNumber))
        elif stack:
            stack[-1].parts.append(" ")  # 하위 태그 앞뒤의 글자가 붙어 다른 단어가 되지 않게 한다.
            if tag == "include":
                stack[-1].parts.append(("include", attrs.get("refid", "")))

    def on_end(tag):
        if not stack:
            return
        stack[-1].parts.append(" ")
        if tag == stack[-1].kind:
            block = stack.pop()
            block.end = parser.CurrentLineNumber
            blocks.append(block)

    def on_text(data):
        if stack:
            stack[-1].parts.append(data)

    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.CharacterDataHandler = on_text
    parser.Parse(text, True)
    return namespace[0], blocks


def _expand(block: _Block, namespace: str, fragments: dict, errors: list[str], used: list, seen: tuple = ()) -> str:
    out = []
    for part in block.parts:
        if isinstance(part, str):
            out.append(part)
            continue
        refid = part[1]
        key = tuple(refid.rsplit(".", 1)) if "." in refid else (namespace, refid)
        if key in seen:
            errors.append(f"{namespace}.{block.id}: include 순환 {refid}")
        elif key not in fragments:
            errors.append(f"{namespace}.{block.id}: include를 찾지 못함 {refid}")
        else:
            target = fragments[key]
            used.append((target.file, target.start, target.end))
            out.append(_expand(target, key[0], fragments, errors, used, (*seen, key)))
    return "".join(out)


def parse_mappers(snapshot: Snapshot) -> MapperIndex:
    index = MapperIndex()
    parsed: list[tuple[str, str, _Block]] = []
    fragments: dict[tuple[str, str], _Block] = {}
    for entry in snapshot.files:
        if entry.language != "xml":
            continue
        raw = (snapshot.root / entry.path).read_bytes()
        try:
            namespace, blocks = _parse_file(raw)
        except expat.ExpatError as e:
            if b"<mapper" in raw:
                index.errors.append(f"{entry.path}: XML을 읽지 못함 ({e})")
            continue
        for block in blocks:
            block.file = entry.path
            parsed.append((entry.path, namespace, block))
            if block.kind == "sql":
                fragments[(namespace, block.id)] = block

    for path, namespace, block in parsed:
        if block.kind == "sql":
            continue
        used: list[tuple[str, int, int]] = []
        sql = _expand(block, namespace, fragments, index.errors, used).strip()
        tables = {t.upper() for t in TABLE_RE.findall(sql)} - NOT_TABLES
        index[(namespace, block.id)] = MapperStatement(
            namespace=namespace, id=block.id, kind=block.kind, file=path, start=block.start, end=block.end, sql=sql,
            tables=tables, dollar_params=set(DOLLAR_RE.findall(sql)), hash_params=set(HASH_RE.findall(sql)),
            fragments=used,
        )
    return index
