"""엔진(taki)과 서버(taki.api·taki.store)의 import 경계. 서버를 다른 저장소로 옮길 수 있는지 지킨다."""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
SERVER = ("taki.api", "taki.store")
PUBLIC = {"taki", "taki.service"}
# CLI의 서버 명령은 _service() 안에서만 서버를 지연 import한다. 다음 PR(3b)에서 서버 코드를 지울 때 이 예외도 지운다.
LAZY_SERVER_IMPORT = ("taki.cli.main", "_service")


def _is(name: str, packages) -> bool:
    return any(name == p or name.startswith(p + ".") for p in packages)


def _is_module(name: str) -> bool:
    path = SRC.joinpath(*name.split("."))
    return path.is_dir() or path.with_suffix(".py").exists()


def _imports(module: str, tree: ast.Module) -> set[str]:
    nodes = [n for n in tree.body
             if not (isinstance(n, ast.FunctionDef) and (module, n.name) == LAZY_SERVER_IMPORT)]
    names: set[str] = set()
    for node in (sub for n in nodes for sub in ast.walk(n)):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{module}: 상대 import는 경계 검사가 읽지 못한다"
            names.add(node.module)
            # `from taki import config`처럼 하위 모듈을 꺼내는 경우도 잡는다.
            names |= {f"{node.module}.{a.name}" for a in node.names if _is_module(f"{node.module}.{a.name}")}
    return {n for n in names if _is(n, ["taki"])}


def _modules() -> dict[str, set[str]]:
    found = {}
    for path in (SRC / "taki").rglob("*.py"):
        module = ".".join(path.relative_to(SRC).with_suffix("").parts).removesuffix(".__init__")
        found[module] = _imports(module, ast.parse(path.read_text(encoding="utf-8")))
    return found


def test_engine_does_not_import_server():
    bad = {m: sorted(n for n in names if _is(n, SERVER)) for m, names in _modules().items() if not _is(m, SERVER)}
    assert {m: v for m, v in bad.items() if v} == {}


def test_server_imports_only_public_engine():
    bad = {m: sorted(n for n in names if not _is(n, SERVER) and n not in PUBLIC)
           for m, names in _modules().items() if _is(m, SERVER)}
    assert {m: v for m, v in bad.items() if v} == {}
