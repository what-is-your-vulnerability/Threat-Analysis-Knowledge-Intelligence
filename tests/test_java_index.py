from pathlib import Path

import pytest

from taki.adapters.lang.java_index import build_index
from taki.schemas.models import Certainty
from taki.steps.scope import scan_scope

FIX = Path(__file__).parent / "fixtures" / "java_calls"
CANONICAL = Path(__file__).resolve().parents[2] / "benchmarks" / "canonical-bss" / "impl" / "java"


@pytest.fixture(scope="module")
def index():
    return build_index(scan_scope(FIX))


def call(index, caller, name):
    return next(c for c in index.calls_from(caller) if c.name == name)


def resolve(index, caller, name):
    return index.resolve_call(caller, call(index, caller, name))


def test_same_variable_name_different_types(index):
    assert resolve(index, "AService.run", "save").targets == ["ARepo.save"]
    assert resolve(index, "BService.run", "save").targets == ["BRepo.save/1"]


def test_constructor_injection_type(index):
    r = resolve(index, "Caller.useMapper", "findById")
    assert r.targets == ["AccountMapper.findById"] and r.certainty == Certainty.code_read and not r.external


def test_interface_resolves_to_mapper_or_impl(index):
    assert resolve(index, "Caller.useInterface", "send").targets == ["SmsSender.send"]
    assert index.implementors("Sender") == ["SmsSender"]


def test_overload_by_arg_count(index):
    assert resolve(index, "BService.runTwo", "save").targets == ["BRepo.save/2"]


def test_method_reference_counted(index):
    assert resolve(index, "Caller.useMethodReference", "toItem").targets == ["ItemMapper.toItem"]


def test_ambiguous_call_keeps_candidates(index):
    r = resolve(index, "Caller.useAmbiguous", "charge")
    assert sorted(r.targets) == ["BankPay.charge", "CardPay.charge"] and r.certainty == Certainty.inferred


def test_unresolved_call_recorded(index):
    r = resolve(index, "Caller.useMissing", "missing")
    assert r.targets == [] and not r.external
    assert index.unresolved_calls("Caller.useMissing") == ["aRepo.missing"]


def test_external_call_is_not_unresolved(index):
    r = resolve(index, "Caller.useExternal", "now")
    assert r.external and r.targets == []
    assert index.unresolved_calls("Caller.useExternal") == []


def test_own_method_call(index):
    assert resolve(index, "Caller.useLocal", "helper").targets == ["Caller.helper"]


def test_generated_accessors_are_not_unresolved(index):
    assert index.unresolved_calls("Caller.useRecordAccessor") == []
    assert index.unresolved_calls("Caller.useLombok") == []


def test_local_var_and_chain(index):
    assert resolve(index, "Caller.useVar", "save").targets == ["ARepo.save"]
    assert index.unresolved_calls("Caller.useChain") == []


def test_enum_members_are_read(index):
    assert resolve(index, "Caller.useEnum", "parse").targets == ["Sort.parse"]
    assert resolve(index, "Caller.useEnum", "value").targets == ["Sort.value"]
    assert index.cls("Sort").fields["value"] == "String"


def test_reflection_is_unresolved(index):
    assert index.unresolved_calls("Caller.useReflection") == ["m.invoke"]


def test_unknown_receiver_falls_back_to_name(index):
    r = resolve(index, "Caller.useUnknownReceiver", "save")
    assert r.certainty == Certainty.inferred and "ARepo.save" in r.targets
    assert index.unresolved_calls("Caller.useUnknownName") == []


def test_field_usages_cross_java_and_xml(tmp_path):
    (tmp_path / "A.java").write_text("class A {\n  private long accountId;\n  long getAccountId() { return accountId; }\n}\n")
    (tmp_path / "m.xml").write_text("<mapper namespace='x'>\n<select id='a'>\nSELECT * FROM T WHERE ACCOUNT_ID = #{accountId}\n"
                                    "</select>\n</mapper>\n")
    usages = build_index(scan_scope(tmp_path)).field_usages("accountId")
    assert {(u.file, u.line) for u in usages} == {("A.java", 2), ("A.java", 3), ("m.xml", 3)}


def test_shared_state_finds_static_cache(index):
    found = {(f.kind, f.symbol) for f in index.shared_state()}
    assert ("static_field", "Cache.SHARED") in found and ("static_field", "Cache.counter") in found
    assert ("map_cache", "Cache.perTenant") in found and ("bean_mutable_field", "Cache.lastUser") in found
    assert ("cacheable", "Cache.load") in found
    assert not any(symbol in ("Cache.LIMIT", "Cache.accountMapper") for _, symbol in found)


@pytest.mark.skipif(not CANONICAL.exists(), reason="정본 없음")
def test_canonical_has_no_unresolved_in_member_delete():
    index = build_index(scan_scope(CANONICAL))
    assert index.method("MemberAdminService.delete") is not None
    assert index.unresolved_calls("MemberAdminService.delete") == []
    everywhere = {s: u for s in index.symbols() if (u := index.unresolved_calls(s))}
    assert everywhere == {}
