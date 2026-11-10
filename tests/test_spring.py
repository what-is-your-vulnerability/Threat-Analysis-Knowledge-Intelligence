from pathlib import Path

import pytest
import yaml

from agent.adapters.lang.java_index import build_index
from agent.adapters.lang.spring import extract_spring
from agent.schemas.models import Capability, Certainty
from agent.steps.scope import scan_scope

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "benchmarks" / "canonical-bss"
FIX = Path(__file__).parent / "fixtures" / "spring-members"
needs_canonical = pytest.mark.skipif(not CANONICAL.exists(), reason="정본 없음")
POM = "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>\n"
CONTROLLER = """package x;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping({prefix})
public class C {{
    {annotation}
    public void h() {{}}
}}
"""


def extract(root):
    snapshot = scan_scope(root)
    return extract_spring(snapshot, build_index(snapshot))


def by_route(result):
    return {(e.method, e.path_template): e for e in result.entrypoints}


def app(tmp_path, annotation='@GetMapping("/a")', prefix='"/p"', extra=""):
    (tmp_path / "pom.xml").write_text(POM)
    (tmp_path / "C.java").write_text(CONTROLLER.format(prefix=prefix, annotation=annotation))
    if extra:
        (tmp_path / "Security.java").write_text(extra)
    return tmp_path


@pytest.fixture(scope="module")
def canonical():
    return by_route(extract(CANONICAL / "impl" / "java"))


@needs_canonical
def test_canonical_matches_openapi_20_operations(canonical):
    spec = yaml.safe_load((CANONICAL / "api" / "dev.openapi.yaml").read_text(encoding="utf-8"))
    base = spec["servers"][0]["url"]
    verbs = {"get", "post", "put", "patch", "delete"}
    expected = {(v.upper(), base + p) for p, item in spec["paths"].items() for v in item if v in verbs}
    assert len(expected) == 20 and set(canonical) == expected


def test_class_and_method_mapping_joined(tmp_path):
    result = extract(app(tmp_path, '@DeleteMapping("/members/{account_id}")', '"/api/v1/admin"'))
    entry = result.entrypoints[0]
    assert (entry.method, entry.path_template) == ("DELETE", "/api/v1/admin/members/{account_id}")
    assert entry.registration_kind == "annotation" and entry.handler_symbol == "C.h" and entry.line == 6
    assert entry.id.endswith(":DELETE:/api/v1/admin/members/{}")


def test_array_and_request_mapping_method(tmp_path):
    annotation = '@RequestMapping(path = {"/a", "/b"}, method = {RequestMethod.GET, RequestMethod.POST})'
    assert set(by_route(extract(app(tmp_path, annotation)))) == {
        ("GET", "/p/a"), ("POST", "/p/a"), ("GET", "/p/b"), ("POST", "/p/b")}


def test_context_path_and_placeholder_from_config(tmp_path):
    app(tmp_path, '@GetMapping("${app.base}/x")')
    (tmp_path / "application.yml").write_text("server:\n  servlet:\n    context-path: /ctx\napp:\n  base: /v2\n")
    assert list(by_route(extract(tmp_path))) == [("GET", "/ctx/p/v2/x")]


@needs_canonical
def test_member_delete_guards(canonical):
    guards = canonical[("DELETE", "/api/v1/admin/members/{account_id}")].effective_guards
    assert "hasRole('ADMIN')" in guards and "authenticated" in guards


@needs_canonical
def test_permit_all_first_match(canonical):
    assert canonical[("POST", "/api/v1/auth/login")].effective_guards == ["permitAll"]
    wildcard = canonical[("POST", "/api/v1/signup/identity-verifications/{verification_id}/complete")]
    assert wildcard.effective_guards == ["permitAll"]


@needs_canonical
def test_filter_added_to_middleware(canonical):
    entry = canonical[("DELETE", "/api/v1/admin/members/{account_id}")]
    assert "SessionAccountFilter" in [g.symbol for g in entry.middleware] and entry.middleware_complete


@needs_canonical
def test_dispatcher_matcher_not_first_match(canonical):
    assert "permitAll" not in canonical[("GET", "/api/v1/me/profile")].effective_guards


def test_first_matching_rule_wins(tmp_path):
    chain = """import org.springframework.context.annotation.Bean;
class Security {
  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a
        .requestMatchers("/p/**").hasRole("ADMIN")
        .requestMatchers("/p/a").permitAll()
        .anyRequest().authenticated()).build();
  }
}
"""
    entry = extract(app(tmp_path, extra=chain)).entrypoints[0]
    assert entry.effective_guards == ["hasRole('ADMIN')"] and entry.middleware_complete


def test_url_rule_with_constant_is_incomplete(tmp_path):
    chain = """class Security {
  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.requestMatchers(PUBLIC).permitAll().anyRequest().authenticated()).build();
  }
}
"""
    entry = extract(app(tmp_path, extra=chain)).entrypoints[0]
    assert not entry.middleware_complete and entry.unresolved_reason


def test_method_security_disabled_is_inferred(tmp_path):
    annotation = '@GetMapping("/a")\n    @org.springframework.security.access.prepost.PreAuthorize("hasRole(\'ADMIN\')")'
    entry = extract(app(tmp_path, annotation)).entrypoints[0]
    assert "hasRole('ADMIN')" not in entry.effective_guards
    assert entry.certainty == Certainty.inferred and entry.unresolved_reason == "METHOD_SECURITY_DISABLED"


def test_method_security_enabled_counts(tmp_path):
    annotation = '@GetMapping("/a")\n    @PreAuthorize("hasRole(\'ADMIN\')")'
    extra = "@Configuration\n@EnableMethodSecurity\nclass Security {}\n"
    entry = extract(app(tmp_path, annotation, extra=extra)).entrypoints[0]
    assert entry.effective_guards == ["hasRole('ADMIN')"] and entry.certainty == Certainty.code_read


def test_class_level_method_security_is_inherited(tmp_path):
    (tmp_path / "pom.xml").write_text(POM)
    (tmp_path / "C.java").write_text('@EnableMethodSecurity @RestController @PreAuthorize("hasRole(\'X\')")\n'
                                     'class C { @GetMapping("/a") void h() {} }\n')
    assert extract(tmp_path).entrypoints[0].effective_guards == ["hasRole('X')"]


def test_demo_vulnerable_delete_has_no_role_guard():
    routes = by_route(extract(FIX / "vulnerable"))
    assert routes[("DELETE", "/api/v1/admin/members/{id}")].effective_guards == ["authenticated"]
    assert "hasRole('ADMIN')" in routes[("POST", "/api/v1/admin/members/{id}/suspend")].effective_guards
    fixed = by_route(extract(FIX / "fixed"))
    assert "hasRole('ADMIN')" in fixed[("DELETE", "/api/v1/admin/members/{id}")].effective_guards


def test_unresolved_path_marks_incomplete(tmp_path):
    entry = extract(app(tmp_path, '@GetMapping("${app.base}/x")')).entrypoints[0]
    assert not entry.middleware_complete and entry.unresolved_reason == "DYNAMIC_PATH"


def test_custom_annotation_marks_incomplete(tmp_path):
    app(tmp_path, '@GetMapping("/a")\n    @AdminOnly')
    (tmp_path / "AdminOnly.java").write_text("public @interface AdminOnly {}\n")
    entry = extract(tmp_path).entrypoints[0]
    assert not entry.middleware_complete and entry.unresolved_reason == "CUSTOM_ANNOTATION"


def test_interceptor_path_patterns(tmp_path):
    config = """class Web implements WebMvcConfigurer {
  public void addInterceptors(InterceptorRegistry r) {
    r.addInterceptor(new AuthInterceptor()).addPathPatterns("/p/**").excludePathPatterns("/p/open");
  }
}
"""
    app(tmp_path)
    (tmp_path / "Web.java").write_text(config)
    assert "AuthInterceptor" in [g.symbol for g in extract(tmp_path).entrypoints[0].middleware]


def test_component_filter_is_global(tmp_path):
    app(tmp_path)
    (tmp_path / "F.java").write_text("@Component\nclass F extends OncePerRequestFilter {}\n")
    assert [g.symbol for g in extract(tmp_path).entrypoints[0].middleware] == ["F"]


def test_filter_registration_bean_marks_incomplete(tmp_path):
    app(tmp_path)
    (tmp_path / "F.java").write_text("class F { @Bean FilterRegistrationBean<X> r() { return null; } }\n")
    result = extract(tmp_path)
    assert not result.entrypoints[0].middleware_complete and result.capabilities["guards"] == Capability.partial


def test_no_controllers_reports_failed(tmp_path):
    (tmp_path / "pom.xml").write_text(POM)
    (tmp_path / "A.java").write_text("class A {}\n")
    result = extract(tmp_path)
    assert result.entrypoints == [] and result.capabilities["entrypoints"] == Capability.failed


def test_non_spring_is_unsupported(tmp_path):
    (tmp_path / "A.java").write_text("class A {}\n")
    assert extract(tmp_path).capabilities["entrypoints"] == Capability.unsupported


def test_spring_detected_from_imports_without_pom(tmp_path):
    (tmp_path / "C.java").write_text(CONTROLLER.format(prefix='"/p"', annotation='@GetMapping("/a")'))
    assert extract(tmp_path).capabilities["entrypoints"] == Capability.supported


def test_url_rule_ignores_context_path(tmp_path):
    chain = """class Security {
  @Bean SecurityFilterChain f(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.requestMatchers("/p/**").denyAll()).build();
  }
}
"""
    app(tmp_path, extra=chain)
    (tmp_path / "application.properties").write_text("server.servlet.context-path=/ctx\n")
    entry = extract(tmp_path).entrypoints[0]
    assert entry.path_template == "/ctx/p/a" and entry.effective_guards == ["denyAll"]


def test_security_dependency_without_rules_is_incomplete(tmp_path):
    app(tmp_path)
    (tmp_path / "pom.xml").write_text("<project><artifactId>spring-boot-starter-security</artifactId></project>\n")
    assert not extract(tmp_path).entrypoints[0].middleware_complete


def test_multiple_filter_chains_are_incomplete(tmp_path):
    chain = """class Security {
  @Bean SecurityFilterChain a(HttpSecurity http) throws Exception {
    return http.securityMatcher("/x/**").authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();
  }
  @Bean SecurityFilterChain b(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
  }
}
"""
    assert not extract(app(tmp_path, extra=chain)).entrypoints[0].middleware_complete
