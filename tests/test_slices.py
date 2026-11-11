import json
from pathlib import Path

import pytest
from conftest import make_config

from taki.adapters.lang.java_index import build_index
from taki.adapters.lang.mybatis import parse_mappers
from taki.adapters.lang.spring import extract_spring
from taki.core.orchestrator import run_scan
from taki.schemas.models import Capability, Role, VerdictState
from taki.steps.cases import load_rules
from taki.steps.scope import scan_scope
from taki.steps.slices import build_slices, fallback_slices, render_slice

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "benchmarks" / "canonical-bss"
FIX = Path(__file__).parent / "fixtures" / "spring-members"
needs_canonical = pytest.mark.skipif(not CANONICAL.exists(), reason="정본 없음")


def slices_of(root, **kw):
    snapshot = scan_scope(root)
    index = build_index(snapshot)
    return snapshot, build_slices(snapshot, extract_spring(snapshot, index).entrypoints, index, parse_mappers(snapshot), **kw)


def lines_of(slice_, snapshot):
    return sum(1 for line in render_slice(slice_, snapshot).split("\n") if "| " in line[:8])


@pytest.fixture(scope="module")
def canonical():
    docs = sorted((CANONICAL / "designs" / "dev").glob("F*.md"))
    snapshot, slices = slices_of(CANONICAL / "impl" / "java", design_docs=docs)
    return snapshot, {s.name: s for s in slices}


@needs_canonical
def test_groups_by_first_fixed_segment(canonical):
    _, slices = canonical
    assert set(slices) == {"admin", "signup", "consultant", "auth", "me"}
    assert len(slices["admin"].flows) == 9 and len(slices["signup"].flows) == 3


@needs_canonical
def test_admin_slice_contents(canonical):
    snapshot, slices = canonical
    admin = slices["admin"]
    files = {Path(f.path).name for f in admin.files}
    assert {"MemberAdminController.java", "MemberViewController.java", "MemberAdminService.java", "AccountMapper.xml",
            "SecurityConfig.java", "SessionAccountFilter.java"} <= files
    assert "SignupService.java" not in files and lines_of(admin, snapshot) <= 1500


@needs_canonical
def test_only_called_methods_are_sent(canonical):
    _, slices = canonical
    names = {Path(f.path).name for f in slices["me"].files}
    assert "SecurityConfig.java" in names and "MemberAdminController.java" not in names and slices["me"].truncated == []
    service = next(f for f in slices["admin"].files if f.path.endswith("MemberAdminService.java"))
    assert service.ranges is not None  # 클래스 전체가 아니라 호출된 메서드만 넣는다


@needs_canonical
def test_view_template_included(canonical):
    _, slices = canonical
    assert "src/main/resources/templates/admin/member-detail.html" in {f.path for f in slices["admin"].files}


@needs_canonical
def test_sql_fragment_lines_are_included(canonical):
    snapshot, slices = canonical
    assert "memberColumns" in render_slice(slices["admin"], snapshot) and "C_RESIDENT_REG_NO" in render_slice(slices["admin"], snapshot)


@needs_canonical
def test_flow_has_hops_in_order(canonical):
    _, slices = canonical
    flow = next(f for f in slices["admin"].flows if f.flow_id == "DELETE /api/v1/admin/members/{account_id}")
    names = [Path(h.file).name for h in flow.hops]
    assert names[0] == "MemberAdminController.java"
    assert names.index("MemberAdminController.java") < names.index("MemberAdminService.java") < names.index("AccountMapper.xml")
    assert flow.hops[0].role == Role.entrypoint
    assert any(h.role == Role.sink and h.file.endswith("AccountMapper.xml") for h in flow.hops)
    assert flow.unresolved == [] and flow.middleware_complete


@needs_canonical
def test_sibling_table_lists_guards(canonical):
    _, slices = canonical
    rows = {f"{r['method']} {r['path']}": r for r in slices["admin"].sibling_table}
    assert "hasRole('ADMIN')" in rows["DELETE /api/v1/admin/members/{account_id}"]["guards"]
    assert rows["POST /api/v1/admin/members/{account_id}/suspend"]["guards"]


@needs_canonical
def test_related_writers_listed(canonical):
    _, slices = canonical
    assert any("ACCOUNT" in r and "/api/v1/signup" in r for r in slices["admin"].related)


@needs_canonical
def test_requirement_mapped_from_design(canonical):
    _, slices = canonical
    assert "F3-admin-members.md#4.6" in slices["admin"].requirement_refs
    row = next(r for r in slices["admin"].sibling_table if r["path"].endswith("{account_id}") and r["method"] == "DELETE")
    assert row["requirement"] == "F3-admin-members.md#4.6"


@needs_canonical
def test_over_budget_splits_and_records_truncation():
    snapshot, slices = slices_of(CANONICAL / "impl" / "java", max_lines=50)
    assert len(slices) > 5 and any(s.truncated for s in slices)
    truncated = next(s for s in slices if s.truncated)
    assert truncated.capability == Capability.partial
    assert all(lines_of(s, snapshot) <= 50 or len(s.files) == 1 for s in slices)
    flows = sorted(f.flow_id for s in slices for f in s.flows)
    assert len(flows) == 20  # 나눠도 API를 버리지 않는다


@needs_canonical
def test_sibling_table_survives_split():
    _, slices = slices_of(CANONICAL / "impl" / "java", max_lines=50)
    deleting = next(s for s in slices if any(f.flow_id.startswith("DELETE /api/v1/admin/members") for f in s.flows))
    assert len(deleting.sibling_table) == 9


def test_single_api_has_empty_sibling_table(tmp_path):
    (tmp_path / "pom.xml").write_text("<project>spring</project>\n")
    (tmp_path / "C.java").write_text('@RestController class C { @GetMapping("/only") void h() {} }\n')
    _, slices = slices_of(tmp_path)
    assert slices[0].sibling_table == [] and any("비교할 API 없음" in r for r in slices[0].related)


def test_mapper_without_statement_is_unresolved(tmp_path):
    (tmp_path / "pom.xml").write_text("<project>spring</project>\n")
    (tmp_path / "C.java").write_text('@RestController class C { private M m; @GetMapping("/a") void h() { m.q(); } }\n')
    (tmp_path / "M.java").write_text("@Mapper interface M { void q(); }\n")
    _, slices = slices_of(tmp_path)
    assert any("M.q" in u for u in slices[0].flows[0].unresolved)


def test_code_hash_changes_with_guard(tmp_path):
    import shutil

    root = tmp_path / "app"
    shutil.copytree(FIX / "vulnerable", root)
    _, before = slices_of(root)
    config = root / "src/main/java/demo/config/SecurityConfig.java"
    config.write_text(config.read_text().replace("authenticated()", "permitAll()"))
    _, after = slices_of(root)
    assert before[0].code_hash != after[0].code_hash


def test_overrides_add_and_remove_files(tmp_path):
    overrides = tmp_path / "over.yml"
    overrides.write_text("- name: admin\n  add_files: [pom.xml]\n  remove_files: [src/main/java/demo/member/MemberService.java]\n")
    _, slices = slices_of(FIX / "vulnerable", overrides=overrides)
    files = {f.path for f in slices[0].files}
    assert "pom.xml" in files and "src/main/java/demo/member/MemberService.java" not in files


def test_no_framework_falls_back_to_partial(tmp_path):
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "app.mjs").write_text("export const a = 1;\n" * 10)
    (tmp_path / "server" / "b.mjs").write_text("export const b = 1;\n" * 10)
    (tmp_path / "web.html").write_text("<p>x</p>\n")
    slices = fallback_slices(scan_scope(tmp_path), max_lines=15)
    assert all(s.capability == Capability.partial for s in slices) and len(slices) >= 3
    assert {f.path for s in slices for f in s.files} == {"server/app.mjs", "server/b.mjs", "web.html"}


def test_e2e_without_manual_slices(fake, tmp_path):
    fake.responses.extend(json.loads((FIX / "fake_script.json").read_text(encoding="utf-8")))
    r = run_scan(FIX / "vulnerable", design=[FIX / "design.md"], out=tmp_path, config=make_config(fake),
                 rules=load_rules(FIX / "rules.yml"))
    assert r.exit_code == 1 and r.findings[0].state == VerdictState.missing_suspected
    assert r.findings[0].root_file.endswith("MemberController.java") and {c.slice_id for c in r.cases} == {"admin"}


def test_spring_without_controllers_exits_3(tmp_path, fake):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "pom.xml").write_text("<project>spring</project>\n")
    r = run_scan(tmp_path / "t", design=[], out=tmp_path / "o", config=make_config(fake))
    assert r.exit_code == 3 and "컨트롤러" in r.error


def test_trimmed_call_code_makes_flow_unresolved():
    _, slices = slices_of(FIX / "vulnerable", max_lines=25)
    delete = next(f for s in slices for f in s.flows if f.flow_id == "DELETE /api/v1/admin/members/{id}")
    assert any("한도로 뺀 코드" in u for u in delete.unresolved)


def test_same_class_name_in_two_packages_is_not_mixed(tmp_path):
    (tmp_path / "pom.xml").write_text("<project>spring</project>\n")
    for pkg in ("a", "b"):
        (tmp_path / pkg).mkdir()
        (tmp_path / pkg / "Repo.java").write_text(f"package {pkg};\npublic class Repo {{ public void remove() {{ int {pkg}Only = 1; }} }}\n")
        (tmp_path / pkg / "MemberController.java").write_text(
            f'package {pkg};\n@RestController class MemberController {{\n  private Repo repo;\n'
            f'  @DeleteMapping("/{pkg}/m") void delete() {{ repo.remove(); }}\n}}\n')
    _, slices = slices_of(tmp_path)
    by_name = {s.name: s for s in slices}
    assert {f.path for f in by_name["a"].files if "MemberController" in f.path} == {"a/MemberController.java"}
    flow = by_name["a"].flows[0]
    assert flow.handler_file == "a/MemberController.java" and any("repo.remove" in u for u in flow.unresolved)
