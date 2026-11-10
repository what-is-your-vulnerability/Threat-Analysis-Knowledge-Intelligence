import pytest

from agent.schemas.models import CheckFailure, Claim, EvidencePath, Flow, Hop, Role
from agent.steps.evidence import check_evidence
from agent.steps.scope import scan_scope

JAVA = """package x;
public class MemberController {
    // 관리자 확인은 게이트웨이에 있음
    @PreAuthorize("hasRole('ADMIN')")
    public void suspend(long id) {
        service.suspend(id);
    }

    public void delete(long id) {
        service.delete(id);
        log("audit only");
    }

    private static final String password = "hunter2hunter2";
    void a() { service.save(id); }
    void b() { service.save(id); }
}
"""
FILE = "MemberController.java"
# 근거 확인 시험용 흐름: 핸들러 범위가 파일 전체라 위치 제한에 걸리지 않는다.
GOOD_FLOW = Flow(flow_id="f1", method="DELETE", path="/m", middleware_complete=True,
                 handler_file="MemberController.java", handler_start=1, handler_end=18)
DELETE_FLOW = Flow(flow_id="DELETE /m", method="DELETE", path="/m", middleware_complete=True,
                   handler_file="MemberController.java", handler_start=9, handler_end=12)


@pytest.fixture
def snapshot(tmp_path):
    (tmp_path / FILE).write_text(JAVA, encoding="utf-8")
    (tmp_path / "mapper.xml").write_text("<!-- hasRole -->\n<select>x</select>\n", encoding="utf-8")
    return scan_scope(tmp_path)


def hop(quote, start=1, end=1, role=Role.root_control, file=FILE):
    return Hop(file=file, start=start, end=end, quote=quote, role=role)


def implemented(*hops, checked="hasRole('ADMIN')", used="hasRole('ADMIN')"):
    return EvidencePath(claim=Claim.implemented, statement="s", hops=list(hops), checked_value=checked, used_value=used)


def absent(**kw):
    values = {"hops": [hop("service.delete(id);", 10, 10)], "expected_positions": ["MemberController.delete"],
              "basis": ["F3#4.6"]}
    return EvidencePath(claim=Claim.absent, statement="s", **{**values, **kw})


def fails(check):
    return set(check.failures)


def test_wrong_line_is_corrected(snapshot):
    check = check_evidence(implemented(hop("@PreAuthorize(\"hasRole('ADMIN')\")", 90, 90)), snapshot, [GOOD_FLOW])
    assert check.passed and (check.fixed_hops[0].start, check.fixed_hops[0].end) == (4, 4)


def test_quote_ignores_surrounding_whitespace(snapshot):
    q = "    public void delete(long id) {\n      service.delete(id);"
    check = check_evidence(absent(hops=[hop(q, 9, 10)]), snapshot, [GOOD_FLOW])
    assert check.passed and (check.fixed_hops[0].start, check.fixed_hops[0].end) == (9, 10)


def test_quote_not_found_fails(snapshot):
    assert CheckFailure.quote_not_found in fails(check_evidence(absent(hops=[hop("nope();")]), snapshot, [GOOD_FLOW]))


def test_file_outside_snapshot_is_not_found(snapshot):
    check = check_evidence(absent(hops=[hop("root:", file="../../etc/passwd")]), snapshot, [GOOD_FLOW])
    assert CheckFailure.quote_not_found in fails(check)


def test_duplicate_quote_outside_range_is_ambiguous(snapshot):
    check = check_evidence(absent(hops=[hop("service.save(id);", 1, 2)]), snapshot, [GOOD_FLOW])
    assert CheckFailure.quote_ambiguous in fails(check)


def test_duplicate_quote_inside_range_passes(snapshot):
    check = check_evidence(absent(hops=[hop("service.save(id);", 16, 16)]), snapshot, [GOOD_FLOW])
    assert check.passed and check.fixed_hops[0].start == 16


def test_quote_in_comment_rejected_for_implemented(snapshot):
    p = implemented(hop("관리자 확인은 게이트웨이에 있음", 3, 3), checked="게이트웨이", used="게이트웨이")
    assert CheckFailure.quote_in_comment in check_evidence(p, snapshot, [GOOD_FLOW]).failures


def test_quote_in_string_rejected_for_implemented(snapshot):
    p = implemented(hop('"audit only"', 11, 11), checked="audit", used="audit")
    assert CheckFailure.quote_in_comment in check_evidence(p, snapshot, [GOOD_FLOW]).failures


def test_string_is_allowed_for_defect_path(snapshot):
    p = EvidencePath(claim=Claim.defect, statement="s", hops=[
        hop("public void delete(long id) {", 9, 9, Role.entrypoint), hop('"audit only"', 11, 11, Role.sink)])
    assert check_evidence(p, snapshot, [GOOD_FLOW]).passed


def test_annotation_string_is_code(snapshot):
    assert check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4)), snapshot, [GOOD_FLOW]).passed


def test_language_without_parser_skips_comment_check(snapshot):
    p = implemented(hop("hasRole", 1, 1, file="mapper.xml"), checked="hasRole", used="hasRole")
    assert check_evidence(p, snapshot, [GOOD_FLOW.model_copy(update={"guard_files": ["mapper.xml"]})]).passed


def test_quote_from_masked_text_matches(snapshot):
    p = absent(hops=[hop('password = "XXXXXXXXXXXXXX"', 14, 14)])
    assert check_evidence(p, snapshot, [GOOD_FLOW]).passed


def test_implemented_needs_binding(snapshot):
    check = check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4), checked=None), snapshot, [GOOD_FLOW])
    assert CheckFailure.no_binding in fails(check)


def test_binding_values_must_be_in_quotes(snapshot):
    check = check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4), used="요청 주체"), snapshot, [GOOD_FLOW])
    assert CheckFailure.no_binding in fails(check)


def test_implemented_needs_quote(snapshot):
    assert not check_evidence(implemented(), snapshot, [GOOD_FLOW]).passed


@pytest.mark.parametrize(
    ("change", "flows", "failure"),
    [
        ({"expected_positions": []}, [GOOD_FLOW], CheckFailure.positions_missing),
        ({"basis": []}, [GOOD_FLOW], CheckFailure.no_basis),
        ({}, [GOOD_FLOW.model_copy(update={"middleware_complete": False})], CheckFailure.middleware_incomplete),
        ({}, [], CheckFailure.middleware_incomplete),
        ({}, [GOOD_FLOW.model_copy(update={"unresolved": ["Foo.bar"]})], CheckFailure.unresolved_links),
    ],
)
def test_absent_needs_all_four(snapshot, change, flows, failure):
    assert failure in fails(check_evidence(absent(**change), snapshot, flows))


def test_absent_with_all_conditions_passes(snapshot):
    assert check_evidence(absent(), snapshot, [GOOD_FLOW]).passed


def test_defect_path_needs_entry_to_outcome(snapshot):
    entry = hop("public void delete(long id) {", 9, 9, Role.entrypoint)
    sink = hop("service.delete(id);", 10, 10, Role.sink)
    good = EvidencePath(claim=Claim.defect, statement="s", hops=[entry, sink])
    no_sink = EvidencePath(claim=Claim.defect, statement="s", hops=[entry])
    no_entry = EvidencePath(claim=Claim.defect, statement="s", hops=[sink])
    assert check_evidence(good, snapshot, [GOOD_FLOW]).passed
    assert CheckFailure.path_broken in fails(check_evidence(no_sink, snapshot, [GOOD_FLOW]))
    assert CheckFailure.path_broken in fails(check_evidence(no_entry, snapshot, [GOOD_FLOW]))


def test_not_applicable_needs_basis(snapshot):
    p = EvidencePath(claim=Claim.not_applicable, statement="공개 API", basis=[])
    assert CheckFailure.no_basis in fails(check_evidence(p, snapshot, [GOOD_FLOW]))


def test_implemented_outside_flow_fails(snapshot):
    # 형제 API(suspend)의 @PreAuthorize를 delete의 구현 근거로 인용
    check = check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4)), snapshot, [DELETE_FLOW])
    assert CheckFailure.off_flow in check.failures


def test_implemented_inside_handler_passes(snapshot):
    p = implemented(hop("service.delete(id);", 10, 10), checked="service.delete(id)", used="service.delete(id)")
    assert check_evidence(p, snapshot, [DELETE_FLOW]).passed


def test_implemented_on_call_path_passes(snapshot):
    path_hop = hop("void a() { service.save(id); }", 15, 15)
    flow = DELETE_FLOW.model_copy(update={"hops": [path_hop.model_copy(update={"end": 15})]})
    p = implemented(hop("void a() { service.save(id); }", 15, 15), checked="service.save", used="service.save")
    assert check_evidence(p, snapshot, [flow]).passed


def test_implemented_in_guard_file_passes(snapshot):
    flow = DELETE_FLOW.model_copy(update={"handler_start": 10, "handler_end": 10, "guard_files": [FILE]})
    assert check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4)), snapshot, [flow]).passed


def test_flow_without_location_cannot_confirm_implemented(snapshot):
    bare = Flow(flow_id="f", method="DELETE", path="/m", middleware_complete=True)
    assert CheckFailure.off_flow in check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4)), snapshot, [bare]).failures
    assert CheckFailure.off_flow in check_evidence(implemented(hop("hasRole('ADMIN')", 4, 4)), snapshot, []).failures


def test_not_applicable_needs_code_quote(snapshot):
    p = EvidencePath(claim=Claim.not_applicable, statement="조회 전용", basis=["설계"])
    assert not check_evidence(p, snapshot, [GOOD_FLOW]).passed


def test_not_applicable_from_comment_is_rejected(snapshot):
    p = EvidencePath(claim=Claim.not_applicable, statement="게이트웨이", basis=["주석"],
                     hops=[hop("관리자 확인은 게이트웨이에 있음", 3, 3)])
    assert CheckFailure.quote_in_comment in check_evidence(p, snapshot, [GOOD_FLOW]).failures
