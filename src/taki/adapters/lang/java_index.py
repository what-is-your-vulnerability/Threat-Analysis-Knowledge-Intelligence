"""tree-sitter로 Java 코드를 읽어 클래스, 메서드, 호출 연결을 찾는다.

범위는 프로젝트 안이고, 밖의 호출은 external로 표시한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from taki.adapters.lang.treesitter import parse_java, walk
from taki.schemas.models import Certainty, Fact, Snapshot

TYPE_DECLARATIONS = {"class_declaration", "interface_declaration", "record_declaration", "enum_declaration"}
ANNOTATION_TYPES = {"annotation", "marker_annotation"}
LOMBOK_ACCESSORS = {"Data", "Getter", "Setter", "Value", "Builder"}
OBJECT_METHODS = {"toString", "equals", "hashCode", "getClass", "values", "valueOf", "name", "ordinal", "compareTo"}
BEAN_ANNOTATIONS = {"Service", "Component", "Repository", "Controller", "RestController"}
INJECTION_ANNOTATIONS = {"Autowired", "Value", "Inject", "Resource"}
REFLECTION_METHODS = {"invoke", "newInstance"}
TEXT_LANGUAGES = {"xml", "html", "sql"}
TOKEN_RE = re.compile(r"[A-Za-z_][\w]*")


@dataclass
class Annotation:
    name: str
    text: str
    line: int
    arguments: Node | None = None


@dataclass
class CallSite:
    name: str
    receiver: str | None
    arg_count: int | None
    line: int
    node: Node = field(repr=False)


@dataclass
class CallTargets:
    targets: list[str]
    certainty: Certainty
    external: bool = False


@dataclass
class JavaMethod:
    symbol: str
    class_name: str
    name: str
    file: str
    start: int
    end: int
    params: dict[str, str | None]
    return_type: str | None
    annotations: list[Annotation]
    node: Node = field(repr=False)
    owner: JavaClass = field(repr=False)  # 같은 이름 클래스가 여럿이어도 자기 클래스를 가리킨다


@dataclass
class JavaClass:
    name: str
    kind: str
    file: str
    start: int
    end: int
    package: str
    imports: dict[str, str]
    annotations: list[Annotation]
    node: Node = field(repr=False)
    fields: dict[str, str | None] = field(default_factory=dict)
    field_nodes: list[Node] = field(repr=False, default_factory=list)
    super_class: str | None = None
    interfaces: list[str] = field(default_factory=list)
    methods: list[JavaMethod] = field(default_factory=list)


def _text(node: Node | None) -> str:
    return (node.text or b"").decode() if node is not None else ""


def _base_type(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "generic_type":
        return _base_type(node.children[0])
    if node.type == "scoped_type_identifier":
        return _text(node).rsplit(".", 1)[-1]
    if node.type == "array_type":
        return _base_type(node.child_by_field_name("element"))
    return _text(node)


def _annotations(owner: Node) -> list[Annotation]:
    found = []
    for child in owner.children:
        if child.type == "modifiers":
            for item in child.children:
                if item.type in ANNOTATION_TYPES:
                    name = _text(item.child_by_field_name("name")).rsplit(".", 1)[-1]
                    found.append(Annotation(name, _text(item), item.start_point[0] + 1,
                                            item.child_by_field_name("arguments")))
    return found


def _modifiers(owner: Node) -> set[str]:
    return {item.type for child in owner.children if child.type == "modifiers" for item in child.children}


def _normalize(name: str) -> str:
    return name.replace("_", "").lower()


class JavaIndex:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self.classes: dict[str, list[JavaClass]] = {}
        self._by_method: dict[str, JavaMethod] = {}
        self._calls: dict[str, list[CallSite]] = {}
        self._method_names: dict[str, list[JavaMethod]] = {}
        self.annotation_types: set[str] = set()
        for entry in snapshot.files:
            if entry.language == "java":
                self._read_file(entry.path)
        self._assign_symbols()

    # 읽기
    def _read_file(self, path: str) -> None:
        tree = parse_java((self.snapshot.root / path).read_bytes())
        package = ""
        imports: dict[str, str] = {}
        for child in tree.root_node.children:
            if child.type == "package_declaration":
                package = next(_text(c) for c in child.children if c.type in ("identifier", "scoped_identifier"))
            elif child.type == "import_declaration":
                full = next(_text(c) for c in child.children if c.type in ("identifier", "scoped_identifier"))
                imports[full.rsplit(".", 1)[-1]] = full
        for node in walk(tree.root_node):
            if node.type in TYPE_DECLARATIONS:
                self._read_class(node, path, package, imports)
            elif node.type == "annotation_type_declaration":
                self.annotation_types.add(_text(node.child_by_field_name("name")))

    def _read_class(self, node: Node, path: str, package: str, imports: dict[str, str]) -> None:
        kind = node.type.removesuffix("_declaration")
        cls = JavaClass(name=_text(node.child_by_field_name("name")), kind=kind, file=path,
                        start=node.start_point[0] + 1, end=node.end_point[0] + 1, package=package, imports=imports,
                        annotations=_annotations(node), node=node)
        superclass = node.child_by_field_name("superclass")
        if superclass is not None:
            cls.super_class = _base_type(next(c for c in superclass.children if c.type != "extends"))
        for child in node.children:
            if child.type in ("super_interfaces", "extends_interfaces"):
                for item in walk(child):
                    if (item.type in ("type_identifier", "scoped_type_identifier")
                            and item.parent.type not in ("scoped_type_identifier", "type_arguments")
                            and (interface := _base_type(item)) is not None):
                        cls.interfaces.append(interface)
        if kind == "record":
            params = node.child_by_field_name("parameters")
            for item in params.children if params is not None else []:
                if item.type == "formal_parameter":
                    cls.fields[_text(item.child_by_field_name("name"))] = _base_type(item.child_by_field_name("type"))
        for member in self._members(node):
            if member.type == "field_declaration":
                cls.field_nodes.append(member)
                for declarator in member.children:
                    if declarator.type == "variable_declarator":
                        name = _text(declarator.child_by_field_name("name"))
                        cls.fields[name] = _base_type(member.child_by_field_name("type"))
            elif member.type == "method_declaration":
                cls.methods.append(self._read_method(member, cls))
        self.classes.setdefault(cls.name, []).append(cls)

    @staticmethod
    def _members(node: Node) -> list[Node]:
        body = node.child_by_field_name("body")
        if body is None:
            body = next((c for c in node.children if c.type == "enum_body"), None)
        members = []
        for child in body.children if body is not None else []:
            # enum은 상수 뒤의 필드와 메서드를 enum_body_declarations로 한 번 더 감싼다.
            members += child.children if child.type == "enum_body_declarations" else [child]
        return members

    def _read_method(self, node: Node, cls: JavaClass) -> JavaMethod:
        params: dict[str, str | None] = {}
        parameters = node.child_by_field_name("parameters")
        for item in parameters.children if parameters is not None else []:
            if item.type in ("formal_parameter", "spread_parameter"):
                name = item.child_by_field_name("name")
                if name is not None:
                    params[_text(name)] = _base_type(item.child_by_field_name("type"))
        return JavaMethod(
            owner=cls,
            symbol="",
            class_name=cls.name,
            name=_text(node.child_by_field_name("name")),
            file=cls.file,
            start=node.start_point[0] + 1,
            end=node.end_point[0] + 1,
            params=params,
            return_type=_base_type(node.child_by_field_name("type")),
            annotations=_annotations(node),
            node=node,
        )

    def _assign_symbols(self) -> None:
        for classes in self.classes.values():
            for cls in classes:
                names = [m.name for m in cls.methods]
                # 패키지만 다른 같은 이름 클래스가 있으면 기호가 겹치지 않게 패키지를 붙인다.
                prefix = f"{cls.package}.{cls.name}" if len(classes) > 1 and cls.package else cls.name
                for method in cls.methods:
                    overloaded = names.count(method.name) > 1
                    method.symbol = f"{prefix}.{method.name}" + (f"/{len(method.params)}" if overloaded else "")
                    self._by_method[method.symbol] = method
                    self._method_names.setdefault(method.name, []).append(method)

    # 조회
    def all_classes(self) -> list[JavaClass]:
        return [c for classes in self.classes.values() for c in classes]

    def cls(self, name: str | JavaClass | None) -> JavaClass | None:
        if isinstance(name, JavaClass):
            return name
        found = self.classes.get(name or "")
        return found[0] if found else None

    def symbols(self) -> list[str]:
        return list(self._by_method)

    def method(self, symbol: str) -> JavaMethod | None:
        return self._by_method.get(symbol)

    def implementors(self, interface: str) -> list[str]:
        return sorted(c.name for c in self.all_classes() if interface in c.interfaces)

    def calls_from(self, symbol: str) -> list[CallSite]:
        if symbol in self._calls:
            return self._calls[symbol]
        method = self._by_method[symbol]
        body = method.node.child_by_field_name("body")
        calls: list[CallSite] = []
        for node in walk(body) if body is not None else []:
            if node.type == "method_invocation":
                receiver = node.child_by_field_name("object")
                arguments = node.child_by_field_name("arguments")
                count = sum(c.is_named and c.type != "comment" for c in arguments.children) if arguments else 0
                calls.append(CallSite(_text(node.child_by_field_name("name")), _text(receiver) if receiver else None,
                                      count, node.start_point[0] + 1, node))
            elif node.type == "method_reference":
                named = [c for c in node.children if c.is_named]
                if len(named) >= 2:
                    calls.append(CallSite(_text(named[-1]), _text(named[0]), None, node.start_point[0] + 1, node))
        self._calls[symbol] = calls
        return calls

    # 타입 추론
    def _local_types(self, method: JavaMethod) -> dict[str, str | JavaClass | None]:
        types: dict[str, str | JavaClass | None] = dict(method.params)
        body = method.node.child_by_field_name("body")
        for node in walk(body) if body is not None else []:
            if node.type == "local_variable_declaration":
                declared = _base_type(node.child_by_field_name("type"))
                for declarator in node.children:
                    if declarator.type == "variable_declarator":
                        name = _text(declarator.child_by_field_name("name"))
                        value = declarator.child_by_field_name("value")
                        types[name] = self._expr_type(value, method, types) if declared == "var" else declared
            elif node.type == "inferred_parameters" or node.type == "lambda_expression":
                parameters = node.child_by_field_name("parameters")
                if parameters is not None and parameters.type == "identifier":
                    types[_text(parameters)] = None
                elif parameters is not None:
                    for item in parameters.children:
                        if item.type == "identifier":
                            types[_text(item)] = None
        return types

    def _field_type(self, class_name: str | JavaClass | None, name: str) -> str | None:
        seen = set()
        cls = self.cls(class_name)
        while cls is not None and cls.name not in seen:
            seen.add(cls.name)
            if name in cls.fields:
                return cls.fields[name]
            cls = self.cls(cls.super_class)
        return None

    def _expr_type(self, node: Node | None, method: JavaMethod, types: dict) -> str | JavaClass | None:
        """식의 타입 이름을 돌려준다. 모르면 None이다."""
        if node is None:
            return None
        if node.type == "identifier":
            name = _text(node)
            if name in types:
                return types[name]
            field_type = self._field_type(method.owner, name)
            if field_type:
                return field_type
            return name if name[:1].isupper() else None
        if node.type == "this":
            return method.owner
        if node.type == "field_access":
            owner = self._expr_type(node.child_by_field_name("object"), method, types)
            return self._field_type(owner, _text(node.child_by_field_name("field"))) if owner else None
        if node.type == "object_creation_expression":
            return _base_type(node.child_by_field_name("type"))
        if node.type == "method_invocation":
            owner_node = node.child_by_field_name("object")
            owner = self._expr_type(owner_node, method, types) if owner_node is not None else method.owner
            if owner is None:
                return None
            name = _text(node.child_by_field_name("name"))
            found = self._find_in_hierarchy(owner, name, None)
            if found:
                return found[0].return_type
            target = self.cls(owner)
            if target is not None and name in target.fields:
                return target.fields[name]
            return "<external>" if target is None else None
        if node.type == "parenthesized_expression":
            return self._expr_type(node.children[1], method, types)
        if node.type == "cast_expression":
            return _base_type(node.child_by_field_name("type"))
        if node.type == "string_literal":
            return "String"
        return None

    def _find_in_hierarchy(self, class_name: str | JavaClass, name: str, arg_count: int | None) -> list[JavaMethod]:
        seen = set()
        pending: list[str | JavaClass] = [class_name]
        while pending:
            current = pending.pop(0)
            cls = self.cls(current)
            if cls is None or id(cls) in seen:
                continue
            seen.add(id(cls))
            matches = [m for m in cls.methods if m.name == name]
            exact = [m for m in matches if arg_count is None or len(m.params) == arg_count]
            if exact or matches:
                return exact or matches
            pending += [p for p in [cls.super_class, *cls.interfaces] if p]
        return []

    def _has_external_parent(self, class_name: str | JavaClass) -> bool:
        seen = set()
        pending: list[str | JavaClass] = [class_name]
        while pending:
            current = pending.pop(0)
            cls = self.cls(current)
            if cls is None:
                return True
            if id(cls) in seen:
                continue
            seen.add(id(cls))
            pending += [p for p in [cls.super_class, *cls.interfaces] if p]
        return False

    def _is_generated(self, cls: JavaClass, name: str) -> bool:
        if name in OBJECT_METHODS:
            return True
        if cls.kind == "record" and name in cls.fields:
            return True
        annotated = {a.name for a in cls.annotations} & LOMBOK_ACCESSORS
        stripped = re.sub(r"^(get|set|is)", "", name)
        known = {_normalize(f) for f in cls.fields}
        return (bool(annotated) and _normalize(stripped) in known) or (bool(annotated) and name in ("builder", "build"))

    def _resolve_in_class(self, owner: str | JavaClass, call: CallSite) -> CallTargets:
        found = self._find_in_hierarchy(owner, call.name, call.arg_count)
        cls = self.cls(owner)
        if found:
            method = found[0]
            declaring = method.owner
            if declaring.kind == "interface":
                implementations = [
                    m.symbol
                    for impl in self.implementors(declaring.name)
                    for m in self._find_in_hierarchy(impl, call.name, call.arg_count)
                ]
                if len(implementations) == 1:
                    return CallTargets(implementations, Certainty.code_read)
                if implementations:
                    return CallTargets(implementations, Certainty.inferred)
            return CallTargets(
                [m.symbol for m in found], Certainty.code_read if len(found) == 1 else Certainty.inferred
            )
        if (cls is not None and self._is_generated(cls, call.name)) or self._has_external_parent(owner):
            return CallTargets([], Certainty.code_read, external=True)
        return CallTargets([], Certainty.code_read)  # 프로젝트 타입인데 대상을 못 찾았다.

    def resolve_call(self, caller_symbol: str, call: CallSite) -> CallTargets:
        method = self._by_method[caller_symbol]
        receiver_node: Node | None
        if call.node is not None and call.node.type == "method_reference":
            receiver_node = next(c for c in call.node.children if c.is_named)
        else:
            receiver_node = call.node.child_by_field_name("object") if call.node is not None else None

        if receiver_node is None:
            return self._resolve_in_class(method.owner, call)
        if receiver_node.type == "super":
            parent = method.owner.super_class
            if parent is not None and self.cls(parent):
                return self._resolve_in_class(parent, call)
            return CallTargets([], Certainty.code_read, True)

        owner = self._expr_type(receiver_node, method, self._local_types(method))
        if owner == "Method" and call.name in REFLECTION_METHODS:
            return CallTargets([], Certainty.inferred)
        if isinstance(owner, str) and len(self.classes.get(owner, [])) > 1:
            return CallTargets([], Certainty.inferred)  # 같은 이름 클래스가 여럿이라 어느 쪽인지 모른다
        if owner is not None and self.cls(owner) is not None:
            return self._resolve_in_class(owner, call)
        if owner is not None:
            return CallTargets([], Certainty.code_read, external=True)

        # 수신 타입을 모른다(람다 인자 등). 프로젝트에 같은 이름이 있으면 후보로 남기고, 없으면 외부로 본다.
        candidates = [m for m in self._method_names.get(call.name, [])
                      if call.arg_count is None or len(m.params) == call.arg_count]
        if candidates:
            return CallTargets([m.symbol for m in candidates], Certainty.inferred)
        return CallTargets([], Certainty.inferred, external=True)

    def unresolved_calls(self, symbol: str) -> list[str]:
        """프로젝트 안에서 대상을 못 찾은 호출과 리플렉션. 이 목록이 있으면 '없다'는 주장을 입증하지 못한다."""
        unresolved = []
        for call in self.calls_from(symbol):
            result = self.resolve_call(symbol, call)
            if not result.targets and not result.external:
                unresolved.append(f"{call.receiver}.{call.name}" if call.receiver else call.name)
        return unresolved

    # 사실 수집
    def field_usages(self, name: str) -> list[Fact]:
        wanted = _normalize(name)
        accessors = {wanted, f"get{wanted}", f"set{wanted}", f"is{wanted}"}
        facts: dict[tuple[str, int], Fact] = {}

        def add(path, line, token, tool):
            facts.setdefault((path, line), Fact(kind="field_usage", file=path, line=line, symbol=token, tool=tool,
                                                detail={"name": name}))

        for entry in self.snapshot.files:
            if entry.language == "java":
                tree = parse_java((self.snapshot.root / entry.path).read_bytes())
                for node in walk(tree.root_node):
                    if node.type == "identifier" and _normalize(_text(node)) in accessors:
                        add(entry.path, node.start_point[0] + 1, _text(node), "java_index")
            elif entry.language in TEXT_LANGUAGES:
                text = (self.snapshot.root / entry.path).read_text(encoding="utf-8", errors="replace")
                for number, line in enumerate(text.split("\n"), start=1):
                    for token in TOKEN_RE.findall(line):
                        if _normalize(token) == wanted:
                            add(entry.path, number, token, "text_search")
        return sorted(facts.values(), key=lambda f: (f.file, f.line))

    def shared_state(self) -> list[Fact]:
        facts = []

        def add(kind, cls, symbol, line, detail=None):
            facts.append(Fact(kind=kind, file=cls.file, line=line, symbol=f"{cls.name}.{symbol}", tool="java_index",
                              detail=detail or {}))

        for cls in self.all_classes():
            is_bean = bool({a.name for a in cls.annotations} & BEAN_ANNOTATIONS)
            for node in cls.field_nodes:
                modifiers = _modifiers(node)
                type_name = _base_type(node.child_by_field_name("type")) or ""
                injected = {a.name for a in _annotations(node)} & INJECTION_ANNOTATIONS
                is_map = type_name.endswith("Map")
                for declarator in node.children:
                    if declarator.type != "variable_declarator":
                        continue
                    name = _text(declarator.child_by_field_name("name"))
                    line = node.start_point[0] + 1
                    if "static" in modifiers:
                        if "final" not in modifiers or is_map or type_name.endswith(("List", "Set", "Cache")):
                            add("static_field", cls, name, line, {"type": type_name})
                    elif is_bean and is_map:
                        add("map_cache", cls, name, line, {"type": type_name})
                    elif is_bean and "final" not in modifiers and not injected:
                        add("bean_mutable_field", cls, name, line, {"type": type_name})
            for method in cls.methods:
                for annotation in method.annotations:
                    if annotation.name == "Cacheable":
                        add("cacheable", cls, method.name, annotation.line, {"annotation": annotation.text})
        return facts


def build_index(snapshot: Snapshot) -> JavaIndex:
    return JavaIndex(snapshot)
