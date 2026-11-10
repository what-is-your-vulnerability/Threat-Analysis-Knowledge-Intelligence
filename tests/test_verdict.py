import pytest

from agent.schemas.models import (
    Case,
    CaseSource,
    CheckFailure,
    Claim,
    EvidenceCheck,
    EvidencePath,
    Hop,
    Outcome,
    Review,
    ReviewResult,
    Role,
    VerdictState,
)
from agent.steps.verdict import decide, group_findings, policy_outcome

PASS = EvidenceCheck(passed=True)
FAIL = EvidenceCheck(passed=False, failures=[CheckFailure.quote_not_found])
KEPT = Review(result=ReviewResult.kept)
NOT_PROVEN = Review(result=ReviewResult.not_proven)


def path(claim=Claim.absent, file="A.java", symbol="A.delete"):
    return EvidencePath(claim=claim, statement="s", category=2, root_symbol=symbol,
                        hops=[Hop(file=file, start=1, end=1, quote="q", role=Role.root_control)])


REFUTED_WITH_PROOF = Review(result=ReviewResult.refuted, evidence=path(Claim.implemented), evidence_check=PASS)
REFUTED_BAD_PROOF = Review(result=ReviewResult.refuted, evidence=path(Claim.implemented), evidence_check=FAIL)
REFUTED_NO_PROOF = Review(result=ReviewResult.refuted)
REFUTED_WRONG_CLAIM = Review(result=ReviewResult.refuted, evidence=path(Claim.absent), evidence_check=PASS)


@pytest.mark.parametrize(
    ("claim", "check", "reviews", "tool", "rule", "state", "outcome"),
    [
        (Claim.implemented, PASS, [], False, False, VerdictState.implemented, Outcome.pass_),
        (Claim.not_applicable, PASS, [], False, False, VerdictState.not_applicable, None),
        (Claim.absent, PASS, [KEPT], False, False, VerdictState.missing_suspected, Outcome.warn),
        (Claim.defect, PASS, [KEPT], True, True, VerdictState.missing_suspected, Outcome.warn),
        (Claim.absent, PASS, [KEPT] * 3, True, False, VerdictState.missing_suspected, Outcome.block),
        (Claim.absent, PASS, [KEPT] * 3, False, True, VerdictState.missing_suspected, Outcome.block),
        (Claim.absent, PASS, [KEPT] * 3, False, False, VerdictState.missing_suspected, Outcome.warn),
        (Claim.absent, FAIL, [], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.absent, PASS, [], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.absent, PASS, [NOT_PROVEN], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.absent, PASS, [REFUTED_WITH_PROOF], False, False, VerdictState.implemented, Outcome.pass_),
        (Claim.absent, PASS, [REFUTED_BAD_PROOF], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.absent, PASS, [REFUTED_NO_PROOF], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.absent, PASS, [REFUTED_WRONG_CLAIM], False, False, VerdictState.unverified, Outcome.warn),
        (Claim.implemented, FAIL, [], False, False, VerdictState.unverified, Outcome.warn),
    ],
)
def test_decision_table(claim, check, reviews, tool, rule, state, outcome):
    v = decide("c1", path(claim), check, reviews, "hash")
    assert v.state == state and v.code_hash == "hash"
    assert policy_outcome(v, tool_confirmed=tool, rule_approved=rule) == outcome


def test_call_failure_is_unverified():
    v = decide("c1", None, None, [], "hash", error="LlmCallError")
    assert v.state == VerdictState.unverified and "LlmCallError" in v.reason and v.claim_key == ""
    assert policy_outcome(v, tool_confirmed=False, rule_approved=False) == Outcome.warn


def test_no_claim_is_unverified():
    assert decide("c1", None, None, [], "hash").state == VerdictState.unverified


def test_refuted_keeps_original_claim():
    v = decide("c1", path(), PASS, [REFUTED_WITH_PROOF], "hash")
    assert v.evidence.claim == Claim.absent and v.reviews[0].evidence.claim == Claim.implemented and v.reason


def test_uses_corrected_lines():
    fixed = Hop(file="A.java", start=9, end=9, quote="q", role=Role.root_control)
    v = decide("c1", path(), EvidenceCheck(passed=True, fixed_hops=[fixed]), [KEPT], "hash")
    assert v.evidence.hops[0].start == 9


def test_claim_key_ignores_line_numbers():
    moved = path().model_copy(update={"hops": [Hop(file="A.java", start=50, end=50, quote="q", role=Role.root_control)]})
    assert decide("c1", path(), PASS, [KEPT], "h").claim_key == decide("c1", moved, PASS, [KEPT], "h").claim_key


def _case(case_id, subject="R1", flow="f1"):
    return Case(case_id=case_id, source=CaseSource.rule, subject_id=subject, question="q", slice_id="s", flow_id=flow)


def test_group_findings_merges_same_root():
    verdicts = [decide("c1", path(), PASS, [KEPT], "h"), decide("c2", path(), PASS, [KEPT], "h")]
    findings = group_findings(verdicts, [_case("c1", flow="f1"), _case("c2", flow="f2")], set())
    assert len(findings) == 1 and findings[0].flows == ["f1", "f2"] and len(findings[0].evidence) == 2
    assert findings[0].broken_rule == "R1" and findings[0].root_file == "A.java"


def test_group_findings_keeps_distinct_roots():
    verdicts = [decide("c1", path(), PASS, [KEPT], "h"), decide("c2", path(symbol="A.purge"), PASS, [KEPT], "h")]
    assert len(group_findings(verdicts, [_case("c1"), _case("c2")], set())) == 2


def test_group_findings_skips_implemented():
    verdicts = [decide("c1", path(Claim.implemented), PASS, [], "h")]
    assert group_findings(verdicts, [_case("c1")], set()) == []


def test_group_findings_prefers_missing_over_unverified():
    verdicts = [decide("c1", path(), FAIL, [], "h"), decide("c2", path(), PASS, [KEPT], "h")]
    finding = group_findings(verdicts, [_case("c1"), _case("c2")], set())[0]
    assert finding.state == VerdictState.missing_suspected and finding.outcome == Outcome.warn


def test_group_findings_blocks_only_with_tool_and_three_reviews():
    v = decide("c1", path(), PASS, [KEPT] * 3, "h")
    first = group_findings([v], [_case("c1")], set())[0]
    assert first.outcome == Outcome.warn
    confirmed = group_findings([v], [_case("c1")], {first.finding_id})[0]
    assert confirmed.outcome == Outcome.block and confirmed.tool_confirmed
