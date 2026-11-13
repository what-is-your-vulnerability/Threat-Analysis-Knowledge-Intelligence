from taki.schemas.models import (
    CaseSource,
    Claim,
    EvidencePath,
    Hop,
    Role,
    VerdictState,
    make_case_id,
    make_finding_id,
)


def test_evidence_path_round_trip():
    p = EvidencePath(
        claim=Claim.absent,
        statement="s",
        cwe="CWE-862",
        category=2,
        hops=[Hop(file="A.java", start=1, end=2, quote="q", role=Role.root_control)],
        expected_positions=["A.java#delete"],
        basis=["F3#4.6"],
    )
    assert EvidencePath.model_validate_json(p.model_dump_json()) == p


def test_ids_ignore_line_numbers():
    assert make_finding_id("A.java", "A.delete", "R1") == make_finding_id("A.java", "A.delete", "R1")
    assert make_case_id(CaseSource.rule, "R1", "admin/members") != make_case_id(CaseSource.rule, "R2", "admin/members")
    assert make_case_id(CaseSource.rule, "R1", "admin", "f1") != make_case_id(CaseSource.rule, "R1", "admin", "f2")


def test_verdict_state_has_no_safe_value():
    assert "safe" not in {s.value for s in VerdictState}
