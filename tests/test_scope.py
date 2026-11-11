import zipfile

import pytest

from taki.adapters.repo.local import ForbiddenPathError, open_target
from taki.schemas.models import Capability
from taki.steps.scope import scan_scope


def _paths(entries):
    return {e.path for e in entries}


def test_mjs_is_counted(tmp_path):
    (tmp_path / "a.mjs").write_text("export const a = 1;\n")
    snap = scan_scope(tmp_path)
    assert [(f.path, f.language, f.lines) for f in snap.files] == [("a.mjs", "javascript", 1)]


def test_unknown_extension_listed_as_not_read(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"abc")
    (tmp_path / "a.py").write_text("x = 1\n")
    snap = scan_scope(tmp_path)
    assert [n.path for n in snap.not_read] == ["x.bin"] and snap.not_read[0].reason


def test_binary_with_known_extension_listed_as_not_read(tmp_path):
    (tmp_path / "a.java").write_bytes(b"class A {\x00}")
    assert "a.java" in _paths(scan_scope(tmp_path).not_read)


@pytest.mark.parametrize("sub", ["ground-truth-private", "authoring", "test-private", "benchmarks/x/work"])
def test_forbidden_paths_rejected(tmp_path, sub):
    target = tmp_path / sub
    target.mkdir(parents=True)
    with pytest.raises(ForbiddenPathError):
        open_target(target, tmp_path / "out")


def test_parent_named_work_is_allowed(tmp_path):
    target = tmp_path / "work" / "Work" / "app"
    target.mkdir(parents=True)
    assert open_target(target, tmp_path / "out") == target.resolve()


def test_symlink_to_forbidden_target_rejected(tmp_path):
    (tmp_path / "ground-truth-private").mkdir()
    link = tmp_path / "innocent"
    link.symlink_to(tmp_path / "ground-truth-private")
    with pytest.raises(ForbiddenPathError):
        open_target(link, tmp_path / "out")


def test_forbidden_child_not_read(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    for name in ("work", "ground-truth-private"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "secret.py").write_text("answer = 1\n")
    snap = scan_scope(tmp_path)
    assert _paths(snap.files) == {"a.py"}
    assert {"work", "ground-truth-private"} <= _paths(snap.not_read)
    assert not any("secret.py" in p for p in _paths(snap.not_read))


def test_excluded_folder_listed(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.js").write_text("1\n")
    snap = scan_scope(tmp_path)
    assert _paths(snap.files) == {"a.py"} and "node_modules" in _paths(snap.not_read)


def test_symlink_inside_target_not_followed(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    (root / "link.py").symlink_to(outside)
    snap = scan_scope(root)
    assert _paths(snap.files) == {"a.py"} and "link.py" in _paths(snap.not_read)


def test_zip_is_extracted(tmp_path):
    z = tmp_path / "src.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("app/a.py", "x = 1\n")
    out = open_target(z, tmp_path / "out")
    assert (out / "app" / "a.py").read_text() == "x = 1\n"


def test_zip_slip_rejected(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../evil.py", "x = 1\n")
    with pytest.raises(ForbiddenPathError):
        open_target(z, tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


def test_empty_project_fails(tmp_path):
    assert scan_scope(tmp_path).status == Capability.failed


def test_project_with_files_is_supported(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert scan_scope(tmp_path).status == Capability.supported


def test_manifest_hash_stable(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    first = scan_scope(tmp_path).manifest_hash
    assert scan_scope(tmp_path).manifest_hash == first
    (tmp_path / "a.py").write_text("x = 2\n")
    assert scan_scope(tmp_path).manifest_hash != first
