"""Spring 진입점과 보안 가드를 코드에서 뽑는다. 못 푼 곳은 숨기지 않고 middleware_complete=False로 남긴다."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import yaml
from tree_sitter import Node

from taki.adapters.lang.java_index import Annotation, JavaIndex, JavaMethod, _text
from taki.adapters.lang.treesitter import walk
from taki.adapters.repo.local import FORBIDDEN_CHILD_NAMES
from taki.config import RULES_DIR
from taki.schemas.models import Capability, Certainty, EntryPoint, Guard, Snapshot
from taki.steps.scope import EXCLUDED_DIRS

PLACEHOLDER_RE = re.compile(r"\$\{([^}:]+)(?::([^}]*))?\}")
PATH_PARAM_RE = re.compile(r"\{[^}]*\}")
FILTER_CALLS = ("addFilterBefore", "addFilterAfter", "addFilterAt")


@lru_cache(maxsize=1)
def _rules() -> dict:
    return yaml.safe_load((RULES_DIR / "frameworks" / "spring.yml").read_text(encoding="utf-8"))


@dataclass
class SpringResult:
    entrypoints: list[EntryPoint] = field(default_factory=list)
    capabilities: dict[str, Capability] = field(default_factory=dict)


@dataclass
class _UrlRule:
    method: str | None
    patterns: list[str] | None  # None이면 anyRequest
    access: str
    symbol: str
    file: str
    line: int


@dataclass
class _Security:
    rules: list[_UrlRule] = field(default_factory=list)
    filters: list[Guard] = field(default_factory=list)
    interceptors: list[tuple[Guard, list[str], list[str]]] = field(default_factory=list)
    incomplete: str | None = None
    method_security: set[str] = field(default_factory=set)  # 실제로 켜진 메서드 보안 애너테이션


def _string(node: Node) -> str | None:
    if node.type == "string_literal":
        return "".join(_text(c) for c in node.children if c.type == "string_fragment")
    return None


def _ant_regex(pattern: str) -> re.Pattern:
    out = ""
    i = 0
    if pattern.endswith("/**"):
        pattern, suffix = pattern[:-3], "(/.*)?"
    else:
        suffix = ""
    while i < len(pattern):
        if pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "{":
            i = pattern.index("}", i) + 1
            out += "[^/]+"
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(f"^{out}{suffix}$")


def _path_matches(patterns: list[str], path: str) -> bool:
    concrete = PATH_PARAM_RE.sub("x", path)
    # URL 규칙과 인터셉터는 컨텍스트 경로를 뺀 경로에 적용된다.
    return any(_ant_regex(p).match(concrete) for p in patterns)


def _chain(node: Node) -> list[Node]:
    """a.b().c() 호출을 앞에서부터 순서대로 돌려준다."""
    top = node
    while (
        top.parent is not None
        and top.parent.type == "method_invocation"
        and top.parent.child_by_field_name("object") == top
    ):
        top = top.parent
    calls = []
    current: Node | None = top
    while current is not None and current.type == "method_invocation":
        calls.append(current)
        current = current.child_by_field_name("object")
    return list(reversed(calls))


def _call_name(node: Node) -> str:
    return _text(node.child_by_field_name("name"))


def _args(node: Node) -> list[Node]:
    arguments = node.child_by_field_name("arguments")
    return [c for c in arguments.children if c.is_named and c.type != "comment"] if arguments else []


def _access_text(call: Node) -> str:
    name = _call_name(call)
    values = [_string(a) or _text(a) for a in _args(call)]
    return f"{name}({', '.join(repr(v) for v in values)})" if values else name


def _read_url_rules(body: Node, file: str, security: _Security) -> None:
    rules = _rules()
    for node in walk(body):
        if node.type != "method_invocation" or _call_name(node) not in ("authorizeHttpRequests", "authorizeRequests"):
            continue
        lambdas = [a for a in _args(node) if a.type == "lambda_expression"]
        if lambdas:
            inner = lambdas[0].child_by_field_name("body")
            calls = _chain(inner) if inner is not None and inner.type == "method_invocation" else []
            if not calls and inner is not None:
                calls = _block_calls(inner)
        else:
            calls = _chain(node)
            calls = calls[[_call_name(c) for c in calls].index(_call_name(node)) + 1 :]
        _rules_from_chain(calls, file, rules, security)


def _block_calls(block: Node) -> list[Node]:
    calls = []
    for node in walk(block):
        if node.type == "method_invocation" and (node.parent.type != "method_invocation"):
            calls += _chain(node)
    return calls


def _rules_from_chain(calls: list[Node], file: str, names: dict, security: _Security) -> None:
    method: str | None = None
    patterns: list[str] | None = []
    pending: bool | None = False
    for call in calls:
        name = _call_name(call)
        if name == "dispatcherTypeMatchers":
            # 요청 경로 규칙이 아니므로 뒤따르는 permitAll까지 건너뛴다.
            pending = None
        elif name in names["url_matchers"]:
            method, patterns, pending = None, [], True
            if name == "anyRequest":
                patterns = None
                continue
            for arg in _args(call):
                value = _string(arg)
                if value is not None:
                    patterns.append(value)
                elif arg.type == "field_access" and _text(arg).startswith("HttpMethod."):
                    method = _text(arg).rsplit(".", 1)[-1]
                else:
                    security.incomplete = f"URL 규칙의 경로를 풀지 못함: {_text(arg)}"
        elif name in names["url_access"]:
            if pending is True:
                access = _access_text(call)
                shown = "anyRequest" if patterns is None else f"{method or ''} {patterns}".strip()
                security.rules.append(
                    _UrlRule(method, patterns, access, f"{shown}.{access}", file, call.start_point[0] + 1)
                )
            pending = False
        elif name == "and":
            break


def _created_type(node: Node | None) -> str:
    return (
        _text(node.child_by_field_name("type"))
        if node is not None and node.type == "object_creation_expression"
        else _text(node)
    )


def _read_filters(index: JavaIndex, security: _Security, capabilities: dict) -> None:
    rules = _rules()
    order = 1
    chains = 0
    for cls in index.all_classes():
        parents = {cls.super_class, *cls.interfaces}
        names = {a.name for a in cls.annotations}
        if parents & set(rules["filter_bases"]) and ("Component" in names or "WebFilter" in names):
            security.filters.append(Guard(order=order, symbol=cls.name, file=cls.file, line=cls.start, scope="global"))
            order += 1
        for method in cls.methods:
            body = method.node.child_by_field_name("body")
            legacy = method.name == "configure" and "WebSecurityConfigurerAdapter" in parents
            if (method.return_type == "SecurityFilterChain" or legacy) and body is not None:
                chains += 1
                _read_url_rules(body, cls.file, security)
                for node in walk(body):
                    if node.type == "method_invocation" and _call_name(node) in FILTER_CALLS:
                        symbol = _created_type(_args(node)[0] if _args(node) else None)
                        security.filters.append(
                            Guard(
                                order=order, symbol=symbol, file=cls.file, line=node.start_point[0] + 1, scope="global"
                            )
                        )
                        order += 1
            if method.return_type == "FilterRegistrationBean":
                security.incomplete = "FilterRegistrationBean의 경로를 풀지 못함"
                capabilities["guards"] = Capability.partial
            if method.name == "addInterceptors" and body is not None:
                _read_interceptors(body, cls.file, security)
        if "Aspect" in names:
            security.incomplete = f"@Aspect 권한 검사를 풀지 못함: {cls.name}"
            capabilities["guards"] = Capability.partial
    if chains > 1:
        security.incomplete = "SecurityFilterChain이 여러 개라 어느 체인이 적용되는지 풀지 못함"
        capabilities["guards"] = Capability.partial


def _read_interceptors(body: Node, file: str, security: _Security) -> None:
    for node in walk(body):
        if node.type != "method_invocation" or _call_name(node) != "addInterceptor":
            continue
        symbol = _created_type(_args(node)[0] if _args(node) else None)
        include, exclude = [], []
        for call in _chain(node):
            values = [_string(a) for a in _args(call)]
            if _call_name(call) == "addPathPatterns":
                include += [v for v in values if v]
            elif _call_name(call) == "excludePathPatterns":
                exclude += [v for v in values if v]
        security.interceptors.append(
            (
                Guard(order=100, symbol=symbol, file=file, line=node.start_point[0] + 1, scope="prefix"),
                include or ["/**"],
                exclude,
            )
        )


def _annotation_values(annotation: Annotation, keys: tuple[str, ...]) -> list[Node]:
    """애너테이션 인자에서 해당 키의 값 노드를 돌려준다. 키 없는 인자는 value로 본다."""
    if annotation.arguments is None:
        return []
    values: list[Node] = []
    for child in annotation.arguments.children:
        if not child.is_named:
            continue
        if child.type == "element_value_pair":
            value = child.child_by_field_name("value")
            if _text(child.child_by_field_name("key")) in keys and value is not None:
                values.append(value)
        elif "value" in keys:
            values.append(child)
    flat: list[Node] = []
    for value in values:
        if value.type == "element_value_array_initializer":
            flat += [c for c in value.children if c.is_named]
        else:
            flat.append(value)
    return flat


def _paths(annotation: Annotation | None) -> list[str | None]:
    """문자열 경로 목록. 상수처럼 풀지 못한 값은 None이다."""
    if annotation is None:
        return [""]
    nodes = _annotation_values(annotation, ("value", "path"))
    return [_string(n) for n in nodes] or [""]


def _resolve_placeholders(path: str, settings: dict[str, str]) -> str | None:
    unresolved = []

    def replace(match):
        value = settings.get(match.group(1), match.group(2))
        if value is None:
            unresolved.append(match.group(1))
            return ""
        return value

    resolved = PLACEHOLDER_RE.sub(replace, path)
    return None if unresolved else resolved


def _join(*parts: str) -> str:
    return re.sub(r"/+", "/", "/" + "/".join(parts)).rstrip("/") or "/"


def _flatten(data, prefix="") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            out |= _flatten(value, f"{prefix}{key}.")
    elif data is not None:
        out[prefix[:-1]] = str(data)
    return out


def _load_settings(snapshot: Snapshot) -> dict[str, str]:
    settings: dict[str, str] = {}
    for entry in snapshot.files:
        name = entry.path.rsplit("/", 1)[-1]
        if not name.startswith("application"):
            continue
        text = (snapshot.root / entry.path).read_text(encoding="utf-8", errors="replace")
        if entry.language == "yaml":
            try:
                for document in yaml.safe_load_all(text):
                    settings |= _flatten(document)
            except yaml.YAMLError:
                continue
        elif entry.language == "properties":
            for line in text.splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, _, value = line.partition("=")
                    settings[key.strip()] = value.strip()
    return settings


def _is_spring(snapshot: Snapshot, index: JavaIndex) -> bool:
    for entry in snapshot.files:
        if entry.path.rsplit("/", 1)[-1] == "pom.xml":
            text = (snapshot.root / entry.path).read_text(encoding="utf-8", errors="replace")
            if "spring" in text:
                return True
    return any(full.startswith("org.springframework") for c in index.all_classes() for full in c.imports.values())


BUILD_FILES = {"pom.xml", "build.gradle", "build.gradle.kts"}
# 스위치마다 옵션이 없을 때 켜지는 애너테이션(Spring Security 기본값).
METHOD_SECURITY_OPTIONS = {
    "prePostEnabled": "PreAuthorize",
    "securedEnabled": "Secured",
    "jsr250Enabled": "RolesAllowed",
}
METHOD_SECURITY_DEFAULTS = {"EnableMethodSecurity": {"PreAuthorize"}, "EnableGlobalMethodSecurity": set()}


def _enabled_method_security(index: JavaIndex) -> set[str]:
    enabled: set[str] = set()
    for cls in index.all_classes():
        for annotation in cls.annotations:
            if annotation.name not in METHOD_SECURITY_DEFAULTS:
                continue
            on = set(METHOD_SECURITY_DEFAULTS[annotation.name])
            for option, target in METHOD_SECURITY_OPTIONS.items():
                values = _annotation_values(annotation, (option,))
                if values:
                    (on.add if _text(values[0]) == "true" else on.discard)(target)
            enabled |= on
    return enabled


def _has_security_dependency(snapshot: Snapshot) -> bool:
    # Gradle 파일은 분석 대상 확장자가 아니라 목록 밖에 있으므로 폴더에서 직접 읽는다.
    skipped = FORBIDDEN_CHILD_NAMES | EXCLUDED_DIRS
    builds = [
        p
        for p in snapshot.root.rglob("*")
        if p.name in BUILD_FILES and not skipped.intersection(p.relative_to(snapshot.root).parts)
    ]
    return any("spring-boot-starter-security" in p.read_text(encoding="utf-8", errors="replace") for p in builds)


def _module_name(snapshot: Snapshot) -> str:
    return snapshot.root.name


def _method_guards(method: JavaMethod, cls_annotations: list[Annotation]) -> list[tuple[str, Annotation]]:
    names = _rules()["method_security"]
    on_method = [a for a in method.annotations if a.name in names]
    chosen = on_method or [a for a in cls_annotations if a.name in names]
    guards = []
    for annotation in chosen:
        values = [_string(v) or _text(v) for v in _annotation_values(annotation, ("value",))]
        if annotation.name == "PreAuthorize":
            guards.append((values[0] if values else annotation.text, annotation))
        else:
            guards.append((f"{annotation.name}({', '.join(values)})", annotation))
    return guards


def _http_methods(annotation: Annotation) -> list[str]:
    mapped = _rules()["mappings"].get(annotation.name)
    if mapped:
        return [mapped]
    nodes = _annotation_values(annotation, ("method",))
    return [_text(n).rsplit(".", 1)[-1] for n in nodes] or ["GET", "POST", "PUT", "PATCH", "DELETE"]


def _first_rule(security: _Security, http_method: str, path: str) -> _UrlRule | None:
    for rule in security.rules:
        if rule.method and rule.method != http_method:
            continue
        if rule.patterns is None or _path_matches(rule.patterns, path):
            return rule
    return None


def _access_guard(access: str) -> str:
    return access.replace('"', "'")


def _build_entry(snapshot, index, cls, method, annotation, http_method, path, app_path, unresolved, security):
    module = _module_name(snapshot)
    guards: list[Guard] = list(security.filters)
    effective: list[str] = []
    certainty = Certainty.code_read
    reason = unresolved
    complete = unresolved is None and security.incomplete is None
    if security.incomplete and reason is None:
        reason = security.incomplete

    for guard, include, exclude in security.interceptors:
        if _path_matches(include, app_path) and not _path_matches(exclude, app_path):
            guards.append(guard)

    rule = _first_rule(security, http_method, app_path)
    if rule:
        guards.append(Guard(order=50, symbol=rule.symbol, file=rule.file, line=rule.line, scope="global"))
        effective.append(_access_guard(rule.access))

    for text, source in _method_guards(method, cls.annotations):
        if source.name in security.method_security:
            guards.append(Guard(order=200, symbol=text, file=cls.file, line=source.line, scope="route"))
            effective.append(text)
        else:
            certainty = Certainty.inferred
            reason = reason or "METHOD_SECURITY_DISABLED"

    known = set(_rules()["mappings"]) | set(_rules()["method_security"]) | {"RequestMapping"}
    custom = {a.name for a in [*method.annotations, *cls.annotations]} & (index.annotation_types - known)
    if custom:
        complete = False
        reason = reason or "CUSTOM_ANNOTATION"

    match_path = PATH_PARAM_RE.sub("{}", path)
    return EntryPoint(
        id=f"EP:{module}:{http_method}:{match_path}",
        method=http_method,
        path_template=path,
        file=cls.file,
        line=annotation.line,
        registration_kind="annotation",
        handler_symbol=method.symbol,
        handler_file=cls.file,
        handler_start=method.start,
        handler_end=method.end,
        middleware=sorted(guards, key=lambda g: g.order),
        effective_guards=effective,
        middleware_complete=complete,
        certainty=certainty,
        unresolved_reason=reason,
    )


def _full_path(context: str, base: str | None, sub: str | None, settings: dict[str, str]) -> tuple[str, str | None]:
    """클래스·메서드 경로를 합친다. 값을 못 정하면 두 번째 값이 DYNAMIC_PATH다."""
    if base is None or sub is None:
        return _join(context, base or "<dynamic>", sub or "<dynamic>"), "DYNAMIC_PATH"
    resolved = _resolve_placeholders(_join(context, base, sub), settings)
    if resolved is None:
        return _join(context, base, sub), "DYNAMIC_PATH"
    return _join(resolved), None


def extract_spring(snapshot: Snapshot, index: JavaIndex) -> SpringResult:
    rules = _rules()
    result = SpringResult()
    if not _is_spring(snapshot, index):
        result.capabilities = {"entrypoints": Capability.unsupported, "guards": Capability.unsupported}
        return result

    result.capabilities = {"entrypoints": Capability.supported, "guards": Capability.supported}
    settings = _load_settings(snapshot)
    context = settings.get("server.servlet.context-path", "")
    security = _Security(method_security=_enabled_method_security(index))
    _read_filters(index, security, result.capabilities)
    if not security.rules and not security.incomplete and _has_security_dependency(snapshot):
        security.incomplete = "Spring Security를 쓰지만 URL 규칙을 찾지 못함"
        result.capabilities["guards"] = Capability.partial

    for cls in index.all_classes():
        if not {a.name for a in cls.annotations} & set(rules["controllers"]):
            continue
        prefix = next((a for a in cls.annotations if a.name == "RequestMapping"), None)
        for method in cls.methods:
            for annotation in method.annotations:
                if annotation.name != "RequestMapping" and annotation.name not in rules["mappings"]:
                    continue
                for base in _paths(prefix):
                    for sub in _paths(annotation):
                        joined, unresolved = _full_path(context, base, sub, settings)
                        for http_method in _http_methods(annotation):
                            result.entrypoints.append(
                                _build_entry(
                                    snapshot,
                                    index,
                                    cls,
                                    method,
                                    annotation,
                                    http_method,
                                    joined,
                                    joined.removeprefix(context) or "/",
                                    unresolved,
                                    security,
                                )
                            )

    for entry in result.entrypoints:
        if entry.unresolved_reason == "DYNAMIC_PATH":
            entry.middleware_complete = False
            result.capabilities["entrypoints"] = Capability.partial
    if not result.entrypoints:
        result.capabilities["entrypoints"] = Capability.failed
    return result
