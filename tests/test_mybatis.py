from pathlib import Path

import pytest

from taki.adapters.lang.mybatis import parse_mappers
from taki.steps.scope import scan_scope

CANONICAL = Path(__file__).resolve().parents[2] / "benchmarks" / "canonical-bss" / "impl" / "java"
needs_canonical = pytest.mark.skipif(not CANONICAL.exists(), reason="정본 없음")
MAPPER = (
    """<?xml version="1.0"?>
<mapper namespace="a.B">
  <sql id="cols">ID, NAME</sql>
  <select id="list">
    SELECT <include refid="cols"/> FROM MEMBER
    <where><if test="q != null">NAME = #{q,jdbcType=VARCHAR}</if></where>
    ORDER BY ${sort}
  </select>
  <insert id="add"><selectKey keyProperty="id">SELECT S.NEXTVAL FROM DUAL</selectKey>"""
    """INSERT INTO MEMBER (ID) VALUES (#{id})</insert>
</mapper>
"""
)


@pytest.fixture
def mappers(tmp_path):
    (tmp_path / "m.xml").write_text(MAPPER)
    (tmp_path / "pom.xml").write_text("<project><artifactId>x</artifactId></project>\n")
    return parse_mappers(scan_scope(tmp_path))


def test_dollar_param_detected(mappers):
    statement = mappers[("a.B", "list")]
    assert statement.dollar_params == {"sort"} and statement.hash_params == {"q"} and statement.kind == "select"


def test_include_expanded(mappers):
    assert "ID, NAME" in mappers[("a.B", "list")].sql


def test_lines_and_tables(mappers):
    statement = mappers[("a.B", "list")]
    assert (statement.start, statement.end) == (4, 8) and statement.file == "m.xml" and statement.tables == {"MEMBER"}
    assert mappers[("a.B", "add")].tables == {"MEMBER"}


def test_other_xml_is_ignored(mappers):
    assert set(mappers) == {("a.B", "list"), ("a.B", "add")} and mappers.errors == []


def test_broken_xml_is_recorded(tmp_path):
    (tmp_path / "bad.xml").write_text('<mapper namespace="x"><select id="a">')
    (tmp_path / "ok.java").write_text("class A {}\n")
    assert "bad.xml" in parse_mappers(scan_scope(tmp_path)).errors[0]


def test_missing_include_is_recorded(tmp_path):
    (tmp_path / "m.xml").write_text(
        '<mapper namespace="x"><select id="a">SELECT <include refid="nope"/></select></mapper>'
    )
    assert "nope" in parse_mappers(scan_scope(tmp_path)).errors[0]


def test_include_cycle_does_not_hang(tmp_path):
    (tmp_path / "m.xml").write_text(
        '<mapper namespace="x"><sql id="a"><include refid="b"/></sql>'
        '<sql id="b"><include refid="a"/></sql>'
        '<select id="s"><include refid="a"/></select></mapper>'
    )
    assert parse_mappers(scan_scope(tmp_path)).errors


@needs_canonical
def test_canonical_account_mapper():
    statement = parse_mappers(scan_scope(CANONICAL))[("com.bss.customer.account.AccountMapper", "findById")]
    assert statement.tables == {"ACCOUNT"} and statement.hash_params == {"accountId"}


@needs_canonical
def test_include_across_namespace():
    mappers = parse_mappers(scan_scope(CANONICAL))
    assigned = mappers[("com.bss.customer.customer.CustomerMapper", "findAssigned")]
    assert "C_RESIDENT_REG_NO" in assigned.sql and assigned.hash_params >= {"consultantId", "offset", "size"}
    assert mappers.errors == []
