import os
import pytest
from sshcfg_lint import lint, main


def msgs(text, **kw):
    return [m for _, _, m in lint(text, check_files=False, **kw)]


def test_clean():
    assert lint("Host a\n  User x\nHost *\n  ForwardAgent no\n", check_files=False) == []


def test_shadowed_by_star_first():
    r = msgs("Host *\n  User root\nHost web\n  User deploy\n")
    assert any("overridden" in m and "root" in m for m in r)


def test_same_value_not_shadowed():
    assert msgs("Host *\n  User x\nHost web\n  User x\n") == []


def test_identityfile_accumulates():
    assert msgs("Host *\n  IdentityFile ~/a\nHost web\n  IdentityFile ~/b\n") == []


def test_duplicate_host():
    assert any("already defined" in m for m in msgs("Host a\n User x\nHost a\n User y\n"))


def test_repeated_key_in_block():
    assert any("repeated" in m for m in msgs("Host a\n User x\n User y\n"))


def test_deprecated():
    assert any("UseRoaming".lower() in m for m in msgs("Host a\n UseRoaming no\n"))


def test_proxyjump_unknown_and_loop():
    r = lint("Host a\n  ProxyJump a\nHost b\n  ProxyJump nope\n", check_files=False)
    assert any(l == "error" for _, l, _ in r)
    assert any("nope" in m for _, _, m in r)


def test_equals_syntax_and_negation():
    r = msgs("Host *\n  User=root\nHost web\n  User=deploy\n")
    assert any("overridden" in m for m in r)
    assert msgs("Host * !web\n  User root\nHost web\n  User deploy\n") == []


def test_key_permissions(tmp_path):
    k = tmp_path / "id"
    k.write_text("x")
    k.chmod(0o644)
    r = lint(f"Host a\n  IdentityFile {k}\n")
    assert any(l == "error" for _, l, _ in r)
    k.chmod(0o600)
    assert lint(f"Host a\n  IdentityFile {k}\n") == []
    assert any("does not exist" in m for _, _, m in lint(f"Host a\n  IdentityFile {tmp_path}/nope\n"))


def test_cli(tmp_path, capsys):
    c = tmp_path / "config"
    c.write_text("Host a\n  ProxyJump a\n")
    c.chmod(0o600)
    assert main([str(c)]) == 1
    c.write_text("Host a\n  User x\n")
    assert main([str(c)]) == 0
    assert main([str(tmp_path / "missing")]) == 2
    c.write_text("Host a\n  User x\nHost a\n")
    assert main([str(c)]) == 0
    assert main(["--strict", str(c)]) == 1
    c.chmod(0o666)
    assert main([str(c)]) == 1
