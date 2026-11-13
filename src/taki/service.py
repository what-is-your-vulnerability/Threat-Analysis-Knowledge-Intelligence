"""CLI와 서버가 함께 쓰는 엔진 흐름. 저장·파일 쓰기는 부른 쪽이 한다."""

from __future__ import annotations

from pathlib import Path

from taki.adapters.lang.java_index import build_index
from taki.adapters.lang.spring import extract_spring
from taki.config import AgentConfig
from taki.llm.gateway import LlmGateway
from taki.llm.roles import DerivedRules, derive_rules, load_templates, renumber_after
from taki.steps.scope import scan_scope


def list_entrypoints(target: Path) -> list[str]:
    """대상 코드의 API 진입점을 "METHOD /path" 목록으로 돌려준다."""
    snapshot = scan_scope(target)
    spring = extract_spring(snapshot, build_index(snapshot))
    return [f"{e.method} {e.path_template}" for e in spring.entrypoints]


def derive_project_rules(
    design_paths, target: Path, existing_rule_ids, config: AgentConfig, runs_dir: Path
) -> DerivedRules:
    """설계문서에서 규칙 후보를 뽑아 이미 쓴 ID 뒤로 번호를 매긴다. threats·warnings는 결과에 붙어 있다."""
    derived = derive_rules(
        design_paths, list_entrypoints(target), load_templates(), gateway=LlmGateway(config, runs_dir)
    )
    derived[:] = renumber_after(existing_rule_ids, derived)
    return derived
