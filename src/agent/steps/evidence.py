"""LLM이 낸 근거를 프로그램이 확인한다. 줄 번호와 인용이 실제 코드와 맞는지, 주장에 필요한 조건을 갖췄는지 본다."""

from __future__ import annotations

from pathlib import PurePosixPath

from agent.adapters.lang.treesitter import parse_java, walk
from agent.llm.masking import mask_text
from agent.schemas.models import CheckFailure, Claim, EvidenceCheck, EvidencePath, Flow, Hop, Role, Snapshot

NON_CODE_TYPES = {"line_comment", "block_comment", "string_literal"}
ANNOTATION_TYPES = {"annotation", "marker_annotation"}


def _normalize(text: str) -> str:
    return "\n".join(line.strip() for line in text.split("\n"))


def _find_all(haystack: str, needle: str) -> list[int]:
    found, at = [], haystack.find(needle)
    while at != -1:
        found.append(at)
        at = haystack.find(needle, at + 1)
    return found


def _candidates(source: str, quote: str) -> list[tuple[int, int, int]]:
    """인용이 나오는 곳을 (시작 줄, 끝 줄, 정규화 본문 위치)로 돌려준다. LLM은 가린 본문을 보므로 둘 다 찾는다."""
    needle = _normalize(quote).strip()
    if not needle:
        return []
    found = {}
    for text in (_normalize(source), _normalize(mask_text(source).text)):
        for at in _find_all(text, needle):
            start = text.count("\n", 0, at) + 1
            found[(start, at)] = (start, start + needle.count("\n"), at)
    return sorted(found.values())


def _locate(hop: Hop, source: str) -> tuple[Hop | None, CheckFailure | None]:
    candidates = _candidates(source, hop.quote)
    if not candidates:
        return None, CheckFailure.quote_not_found
    in_range = [c for c in candidates if hop.start <= c[0] and c[1] <= hop.end]
    if len(in_range) == 1:
        chosen = in_range[0]
    elif len(candidates) == 1:
        chosen = candidates[0]
    else:
        return None, CheckFailure.quote_ambiguous
    return hop.model_copy(update={"start": chosen[0], "end": chosen[1]}), None


def _non_code_ranges(source: bytes) -> list[tuple[int, int]]:
    ranges = []
    for node in walk(parse_java(source).root_node):
        if node.type not in NON_CODE_TYPES:
            continue
        parent = node.parent
        while parent is not None and parent.type not in ANNOTATION_TYPES:
            parent = parent.parent
        if parent is None:  # 애너테이션 인자의 문자열은 실제로 동작하는 코드다.
            ranges.append((node.start_byte, node.end_byte))
    return ranges


def _is_only_comment_or_string(hop: Hop, source: str) -> bool:
    """인용한 줄에서 인용 부분이 전부 주석이나 문자열 안에 있으면 참이다."""
    if PurePosixPath(hop.file).suffix != ".java":
        return False  # 파서가 없는 언어는 판별하지 못하므로 실패로 치지 않는다.
    lines = source.split("\n")
    selected = lines[hop.start - 1 : hop.end]
    masked_lines = mask_text(source).text.split("\n")[hop.start - 1 : hop.end]
    first = _normalize(hop.quote).strip().split("\n")[0]
    column = max(selected[0].find(first), masked_lines[0].find(first), 0)
    last_part = _normalize(hop.quote).strip().split("\n")[-1]
    last_col = max(selected[-1].find(last_part), masked_lines[-1].find(last_part), 0)

    encoded = source.encode()
    start = len("\n".join(lines[: hop.start - 1]).encode()) + (1 if hop.start > 1 else 0)
    start += len(selected[0][:column].encode())
    end = len("\n".join(lines[: hop.end - 1]).encode()) + (1 if hop.end > 1 else 0)
    end += len(selected[-1][: last_col + len(last_part)].encode())

    ranges = _non_code_ranges(encoded)
    return all(
        any(a <= i < b for a, b in ranges) for i in range(start, end) if not chr(encoded[i]).isspace()
    )


def _read(hop_file: str, snapshot: Snapshot, listed: set[str], cache: dict[str, str]) -> str | None:
    if hop_file not in listed:
        return None  # 목록 밖 경로는 읽지 않는다.
    if hop_file not in cache:
        cache[hop_file] = (snapshot.root / hop_file).read_text(encoding="utf-8", errors="replace")
    return cache[hop_file]


def _inside(hop: Hop, flow: Flow) -> bool:
    if hop.file in flow.guard_files:
        return True
    spans = [(flow.handler_file, flow.handler_start, flow.handler_end), *((h.file, h.start, h.end) for h in flow.hops)]
    return any(file == hop.file and start is not None and start <= hop.start and hop.end <= end
               for file, start, end in spans)


def _claim_failures(path: EvidencePath, flows: list[Flow], hops: list[Hop]) -> list[CheckFailure]:
    failures: list[CheckFailure] = []
    if path.claim in (Claim.implemented, Claim.not_applicable):
        if not path.hops:
            failures.append(CheckFailure.quote_not_found)
        # 다른 API의 검사를 이 API의 근거로 인용하는 것을 막는다. 위치를 모르는 흐름이면 확인할 수 없다.
        elif not any(all(_inside(h, flow) for h in hops) for flow in flows):
            failures.append(CheckFailure.off_flow)
    if path.claim == Claim.implemented:
        quotes = [h.quote for h in path.hops]
        bound = path.checked_value and path.used_value and all(
            any(value in q for q in quotes) for value in (path.checked_value, path.used_value)
        )
        if not bound:
            failures.append(CheckFailure.no_binding)
    elif path.claim == Claim.absent:
        if not path.expected_positions:
            failures.append(CheckFailure.positions_missing)
        if not flows or not all(f.middleware_complete for f in flows):
            failures.append(CheckFailure.middleware_incomplete)
        if any(f.unresolved for f in flows):
            failures.append(CheckFailure.unresolved_links)
        if not path.basis:
            failures.append(CheckFailure.no_basis)
    elif path.claim == Claim.defect and (
        not path.hops or path.hops[0].role != Role.entrypoint or path.hops[-1].role not in (Role.sink, Role.outcome)
    ):
        failures.append(CheckFailure.path_broken)
    if path.claim == Claim.not_applicable and not path.basis:
        failures.append(CheckFailure.no_basis)
    return failures


def check_evidence(path: EvidencePath, snapshot: Snapshot, flows: list[Flow]) -> EvidenceCheck:
    listed = {f.path for f in snapshot.files}
    cache: dict[str, str] = {}
    failures: list[CheckFailure] = []
    fixed: list[Hop] = []
    for hop in path.hops:
        source = _read(hop.file, snapshot, listed, cache)
        if source is None:
            failures.append(CheckFailure.quote_not_found)
            fixed.append(hop)
            continue
        located, failure = _locate(hop, source)
        if failure:
            failures.append(failure)
            fixed.append(hop)
            continue
        fixed.append(located)
        if path.claim in (Claim.implemented, Claim.not_applicable) and _is_only_comment_or_string(located, source):
            failures.append(CheckFailure.quote_in_comment)
    failures.extend(_claim_failures(path, flows, fixed))
    return EvidenceCheck(passed=not failures, failures=list(dict.fromkeys(failures)), fixed_hops=fixed)
