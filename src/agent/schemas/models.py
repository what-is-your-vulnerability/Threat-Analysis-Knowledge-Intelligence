"""모든 단계가 함께 쓰는 자료형."""

from __future__ import annotations

import hashlib
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Role(str, Enum):
    entrypoint = "entrypoint"
    propagation = "propagation"
    root_control = "root_control"
    sink = "sink"
    outcome = "outcome"
    expected_control = "expected_control"


class Relation(str, Enum):
    calls = "calls"
    data = "data"
    guards = "guards"
    reads = "reads"
    writes = "writes"
    sibling = "sibling"


class Certainty(str, Enum):
    tool_confirmed = "tool_confirmed"
    code_read = "code_read"
    inferred = "inferred"


class Claim(str, Enum):
    implemented = "implemented"
    absent = "absent"
    defect = "defect"
    not_applicable = "not_applicable"


class VerdictState(str, Enum):
    implemented = "implemented"
    missing_suspected = "missing_suspected"
    unverified = "unverified"
    not_applicable = "not_applicable"


class Outcome(str, Enum):
    pass_ = "pass"
    warn = "warn"
    block = "block"


class CaseSource(str, Enum):
    rule = "rule"
    question = "question"
    alert = "alert"


class Capability(str, Enum):
    supported = "supported"
    partial = "partial"
    unsupported = "unsupported"
    failed = "failed"


class LedgerState(str, Enum):
    checked = "checked"
    deferred = "deferred"
    not_seen = "not_seen"


class RunMode(str, Enum):
    onboard = "onboard"
    full = "full"
    recheck = "recheck"


class ReviewResult(str, Enum):
    kept = "kept"
    refuted = "refuted"
    not_proven = "not_proven"


class RuleStatus(str, Enum):
    pending = "pending"
    approved = "approved"


class CheckFailure(str, Enum):
    quote_not_found = "quote_not_found"
    quote_ambiguous = "quote_ambiguous"
    quote_in_comment = "quote_in_comment"
    no_binding = "no_binding"
    positions_missing = "positions_missing"
    middleware_incomplete = "middleware_incomplete"
    unresolved_links = "unresolved_links"
    no_basis = "no_basis"
    path_broken = "path_broken"


class Disposition(str, Enum):
    issue = "issue"
    no_issue = "no_issue"
    not_applicable = "not_applicable"


class FileEntry(BaseModel):
    path: str
    sha256: str
    language: str
    lines: int


class NotRead(BaseModel):
    path: str
    reason: str


class Snapshot(BaseModel):
    root: Path
    commit: str | None = None
    manifest_hash: str
    files: list[FileEntry] = Field(default_factory=list)
    not_read: list[NotRead] = Field(default_factory=list)
    capabilities: dict[str, Capability] = Field(default_factory=dict)
    status: Capability = Capability.supported


class Fact(BaseModel):
    kind: str
    file: str
    line: int | None = None
    symbol: str | None = None
    detail: dict = Field(default_factory=dict)
    tool: str | None = None
    tool_version: str | None = None
    certainty: Certainty = Certainty.code_read


class Guard(BaseModel):
    order: int
    symbol: str
    file: str | None = None
    line: int | None = None
    scope: str | None = None


class EntryPoint(BaseModel):
    id: str
    method: str
    path_template: str
    file: str
    line: int
    registration_kind: str
    handler_symbol: str
    handler_file: str
    handler_start: int
    handler_end: int
    middleware: list[Guard] = Field(default_factory=list)
    effective_guards: list[str] = Field(default_factory=list)
    middleware_complete: bool = False
    certainty: Certainty = Certainty.code_read
    unresolved_reason: str | None = None


class Hop(BaseModel):
    file: str
    start: int
    end: int
    quote: str
    role: Role
    relation: Relation | None = None
    certainty: Certainty = Certainty.code_read


class Flow(BaseModel):
    flow_id: str
    method: str
    path: str
    handler_symbol: str | None = None
    hops: list[Hop] = Field(default_factory=list)
    guards: list[str] = Field(default_factory=list)
    middleware_complete: bool = False
    unresolved: list[str] = Field(default_factory=list)


class SliceFile(BaseModel):
    path: str
    ranges: list[tuple[int, int]] | None = None


class Slice(BaseModel):
    slice_id: str
    name: str
    flows: list[Flow] = Field(default_factory=list)
    files: list[SliceFile] = Field(default_factory=list)
    sibling_table: list[dict] = Field(default_factory=list)
    requirement_refs: list[str] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)
    code_hash: str = ""
    truncated: list[str] = Field(default_factory=list)
    capability: Capability = Capability.supported


class Budget(BaseModel):
    max_tool_calls: int = 8
    max_input_tokens: int = 60000
    max_output_tokens: int = 6000
    max_seconds: int = 180


class Case(BaseModel):
    case_id: str
    source: CaseSource
    subject_id: str
    question: str
    slice_id: str
    flow_id: str | None = None
    budget: Budget = Field(default_factory=Budget)


class EvidencePath(BaseModel):
    claim: Claim
    statement: str
    cwe: str | None = None
    category: int | None = None
    hops: list[Hop] = Field(default_factory=list)
    checked_value: str | None = None
    used_value: str | None = None
    expected_positions: list[str] = Field(default_factory=list)
    basis: list[str] = Field(default_factory=list)
    counter_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    root_symbol: str | None = None


class EvidenceCheck(BaseModel):
    passed: bool
    failures: list[CheckFailure] = Field(default_factory=list)
    fixed_hops: list[Hop] = Field(default_factory=list)


class Review(BaseModel):
    result: ReviewResult
    reason: str = ""
    evidence: EvidencePath | None = None
    evidence_check: EvidenceCheck | None = None  # 기각 근거를 프로그램이 확인한 결과


class Verdict(BaseModel):
    case_id: str
    claim_key: str = ""
    state: VerdictState
    reason: str = ""
    evidence: EvidencePath | None = None
    check: EvidenceCheck | None = None
    reviews: list[Review] = Field(default_factory=list)
    manifest_ids: list[str] = Field(default_factory=list)
    code_hash: str = ""


class FixProposal(BaseModel):
    location: str
    code_example: str
    check_scenario: str


class Finding(BaseModel):
    finding_id: str
    state: VerdictState
    root_file: str | None = None
    root_symbol: str | None = None
    broken_rule: str | None = None
    cwe: str | None = None
    category: int | None = None
    flows: list[str] = Field(default_factory=list)
    statement: str = ""
    evidence: list[EvidencePath] = Field(default_factory=list)
    fix: FixProposal | None = None
    outcome: Outcome | None = None
    tool_confirmed: bool = False
    case_ids: list[str] = Field(default_factory=list)


class LedgerCell(BaseModel):
    subject: str
    target: str
    state: LedgerState
    reason: str = ""


class LensDisposition(BaseModel):
    lens_id: str
    disposition: Disposition
    reason: str = ""


class SecurityRule(BaseModel):
    rule_id: str
    title: str
    requirement_quote: str | None = None
    doc_ref: str | None = None
    stride: list[str] = Field(default_factory=list)
    category: int | None = None
    cwe: str | None = None
    standard_ref: str | None = None
    applies_to: list[str] = Field(default_factory=list)
    status: RuleStatus = RuleStatus.pending
    version: int = 1
    out_of_standard: bool = False


class ManifestEntry(BaseModel):
    manifest_id: str
    role: str
    model: str | None = None
    prompt_version: str
    case_id: str | None = None
    sent_files: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    error: str | None = None
    messages: list[dict] = Field(default_factory=list)  # 가린 뒤의 프롬프트


def _short_hash(*parts: object) -> str:
    joined = "\x00".join("" if p is None else str(getattr(p, "value", p)) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def make_case_id(source: CaseSource, subject_id: str, slice_name: str, flow_id: str | None = None) -> str:
    return _short_hash(source, subject_id, slice_name, flow_id)


def make_finding_id(root_file: str | None, root_symbol: str | None, broken_rule: str | None) -> str:
    return _short_hash(root_file, root_symbol, broken_rule)


def make_claim_key(root_file: str | None, root_symbol: str | None, category: int | None) -> str:
    return _short_hash(root_file, root_symbol, category)
