"""LLM이 부르는 읽기 전용 도구. 대상 코드 목록 안에서만 읽고, 실패는 오류 문자열로 돌려준다."""

from __future__ import annotations

import json
import re
from pathlib import Path

from taki.llm.masking import mask_file_text

MAX_READ_LINES = 400
MAX_SEARCH_HITS = 50
HEADING_RE = re.compile(r"^(#+)\s+(.*)$")


def _function(tool: str, description: str, **properties) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": list(properties)},
        },
    }


STRING = {"type": "string"}
INTEGER = {"type": "integer"}
SCHEMAS = [
    _function("read_code", "대상 코드의 줄 범위를 줄 번호와 함께 읽는다.", path=STRING, start=INTEGER, end=INTEGER),
    _function("search", "대상 코드에서 글자를 대소문자 구분 없이 찾는다. 정규식이 아니다.", pattern=STRING),
    _function("callers", "이 메서드를 부르는 메서드를 찾는다. 형식은 클래스.메서드다.", symbol=STRING),
    _function("callees", "이 메서드가 부르는 메서드를 찾는다.", symbol=STRING),
    _function("field_usages", "필드, getter, 매퍼 파라미터, 컬럼을 이름으로 찾는다.", name=STRING),
    _function("route_info", "API의 핸들러와 확인된 검사를 돌려준다.", method=STRING, path=STRING),
    _function("read_doc", "설계문서의 한 절을 읽는다.", doc=STRING, section=STRING),
]


class ReadOnlyTools:
    def __init__(self, snapshot, index=None, mappers=None, entrypoints=(), docs=()):
        self.snapshot = snapshot
        self.index = index
        self.mappers = mappers
        self.entrypoints = list(entrypoints)
        self.docs = {Path(d).name: Path(d) for d in docs}
        self.listed = {f.path for f in snapshot.files}

    def schemas(self) -> list[dict]:
        return list(SCHEMAS)

    def call(self, name: str, args: dict) -> str:
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return f"오류: 없는 도구 {name}"
        try:
            return handler(**args)
        except (TypeError, ValueError) as e:
            return f"오류: 잘못된 인자 ({e})"

    def _lines(self, path: str) -> list[str]:
        text = (self.snapshot.root / path).read_text(encoding="utf-8", errors="replace")
        return mask_file_text(path, text).split("\n")

    def _tool_read_code(self, path, start, end) -> str:
        if path not in self.listed:
            return f"오류: 읽을 수 없는 파일 {path}"
        lines = self._lines(path)
        start, end = max(1, int(start)), min(len(lines), int(end), int(start) + MAX_READ_LINES - 1)
        return "\n".join(f"{n:>5}| {lines[n - 1]}" for n in range(start, end + 1))

    def _tool_search(self, pattern) -> str:
        wanted = str(pattern).lower()
        hits = []
        for path in sorted(self.listed):
            for number, line in enumerate(self._lines(path), start=1):
                if wanted in line.lower():
                    hits.append(f"{path}:{number}: {line.strip()}")
                    if len(hits) >= MAX_SEARCH_HITS:
                        return "\n".join([*hits, f"(앞 {MAX_SEARCH_HITS}건만 표시)"])
        return "\n".join(hits) or "없음"

    def _tool_callers(self, symbol) -> str:
        if self.index is None:
            return "오류: 이 언어는 호출 정보를 지원하지 않음"
        found = [
            s
            for s in self.index.symbols()
            for call in self.index.calls_from(s)
            if symbol in self.index.resolve_call(s, call).targets
        ]
        return "\n".join(dict.fromkeys(found)) or "없음"

    def _tool_callees(self, symbol) -> str:
        if self.index is None or self.index.method(symbol) is None:
            return f"오류: 찾을 수 없는 메서드 {symbol}"
        rows = []
        for call in self.index.calls_from(symbol):
            result = self.index.resolve_call(symbol, call)
            target = ", ".join(result.targets) or ("프로젝트 밖" if result.external else "대상을 찾지 못함")
            rows.append(f"{call.line}: {call.name} -> {target} ({result.certainty.value})")
        return "\n".join(rows) or "없음"

    def _tool_field_usages(self, name) -> str:
        if self.index is None:
            return "오류: 이 언어는 필드 정보를 지원하지 않음"
        return "\n".join(f"{u.file}:{u.line}: {u.symbol}" for u in self.index.field_usages(name)) or "없음"

    def _tool_route_info(self, method, path) -> str:
        for entry in self.entrypoints:
            if entry.method == str(method).upper() and entry.path_template == path:
                return json.dumps(entry.model_dump(mode="json"), ensure_ascii=False)
        return f"오류: 찾을 수 없는 API {method} {path}"

    def _tool_read_doc(self, doc, section) -> str:
        path = self.docs.get(doc)
        if path is None:
            return f"오류: 읽을 수 없는 문서 {doc}"
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        out: list[str] = []
        level = None
        for line in lines:
            heading = HEADING_RE.match(line)
            if level is None and heading and section in heading.group(2):
                level = len(heading.group(1))
                out.append(line)
            elif level is not None:
                if heading and len(heading.group(1)) <= level:
                    break
                out.append(line)
        return "\n".join(out) or f"오류: 찾을 수 없는 절 {section}"
