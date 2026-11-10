"""tree-sitter 파서를 한 곳에서 만든다."""

from __future__ import annotations

from functools import lru_cache

import tree_sitter_java
from tree_sitter import Language, Node, Parser, Tree


@lru_cache(maxsize=1)
def _java_parser() -> Parser:
    return Parser(Language(tree_sitter_java.language()))


def parse_java(source: bytes) -> Tree:
    return _java_parser().parse(source)


def walk(node: Node):
    yield node
    for child in node.children:
        yield from walk(child)
