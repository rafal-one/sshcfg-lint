"""Lint an OpenSSH client config (~/.ssh/config): shadowed options, missing keys, loose permissions."""
import argparse
import fnmatch
import os
import re
import stat
import sys

__version__ = "0.1.0"

DEPRECATED = {
    "useroaming": "removed in OpenSSH 7.x, ignored",
    "protocol": "SSH protocol 1 support was removed",
    "rsaauthentication": "protocol 1 only, removed",
    "rhostsrsaauthentication": "protocol 1 only, removed",
    "useprivilegedport": "removed",
}
# first value wins in ssh_config; these accumulate instead
MULTI = {"identityfile", "localforward", "remoteforward", "dynamicforward", "sendenv",
         "setenv", "certificatefile", "canonicaldomains", "permitremoteopen"}


class Entry:
    def __init__(self, line, key, value):
        self.line, self.key, self.value = line, key, value


class Block:
    def __init__(self, line, patterns):
        self.line, self.patterns, self.entries = line, patterns, []


def split_args(s):
    return [a.strip('"') for a in re.findall(r'"[^"]*"|\S+', s)]


def parse(text):
    """Return (blocks, notes). Block 0 holds options before any Host/Match."""
    blocks = [Block(0, ["*"])]
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"(\w+)\s*(?:=\s*|\s+)(.*)$", s)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip()
        if key == "host":
            blocks.append(Block(n, split_args(val)))
        elif key == "match":
            blocks.append(Block(n, ["<match>"]))
        else:
            blocks[-1].entries.append(Entry(n, key, val))
    return blocks


def matches(patterns, host):
    ok = False
    for p in patterns:
        if p.startswith("!"):
            if fnmatch.fnmatchcase(host, p[1:]):
                return False
        elif fnmatch.fnmatchcase(host, p):
            ok = True
    return ok


def lint(text, config_path=None, check_files=True):
    """Return a list of (line, level, message)."""
    out = []
    blocks = parse(text)
    seen = {}
    for b in blocks[1:]:
        for p in b.patterns:
            if p in seen and not p.startswith("!") and p != "<match>":
                out.append((b.line, "warn", f"Host {p!r} already defined at line {seen[p]}"))
            seen.setdefault(p, b.line)
    for b in blocks:
        for e in b.entries:
            if e.key in DEPRECATED:
                out.append((e.line, "warn", f"{e.key}: {DEPRECATED[e.key]}"))
        keys = {}
        for e in b.entries:
            if e.key in keys and e.key not in MULTI:
                out.append((e.line, "warn", f"{e.key} repeated in the same block (line {keys[e.key]}); first value wins"))
            keys.setdefault(e.key, e.line)
    # shadowing: an earlier block that matches the later block's literal host sets the option first
    for i, b in enumerate(blocks):
        if i == 0:
            continue
        hosts = [p for p in b.patterns if not re.search(r"[*?!]", p) and p != "<match>"]
        for e in b.entries:
            if e.key in MULTI:
                continue
            for h in hosts:
                for prev in blocks[:i]:
                    if prev is b or "<match>" in prev.patterns or not matches(prev.patterns, h):
                        continue
                    hit = next((x for x in prev.entries if x.key == e.key), None)
                    if hit and hit.value != e.value:
                        where = "before any Host" if prev.line == 0 else f"Host {' '.join(prev.patterns)} (line {prev.line})"
                        out.append((e.line, "warn",
                                    f"{e.key} {e.value!r} for {h} is overridden by {hit.value!r} at line {hit.line} ({where}); first match wins"))
                        break
                else:
                    continue
                break
    names = {p for b in blocks[1:] for p in b.patterns}
    for b in blocks:
        for e in b.entries:
            if e.key == "proxyjump":
                for hop in e.value.split(","):
                    hop = hop.split("@")[-1].rsplit(":", 1)[0] if "[" not in hop else hop
                    if hop.lower() != "none" and hop not in names and not any(
                            matches(x.patterns, hop) for x in blocks[1:] if x is not b):
                        out.append((e.line, "info", f"ProxyJump {hop!r} has no matching Host entry"))
                    if hop in b.patterns:
                        out.append((e.line, "error", f"ProxyJump {hop!r} points at its own block (loop)"))
            if check_files and e.key in ("identityfile", "certificatefile", "userknownhostsfile") and "%" not in e.value:
                for v in split_args(e.value):
                    path = os.path.expanduser(v)
                    if e.key == "userknownhostsfile" or v.startswith("~") is False and not os.path.isabs(path):
                        continue
                    if not os.path.exists(path):
                        out.append((e.line, "warn", f"{e.key} {v} does not exist"))
                    elif e.key == "identityfile" and os.stat(path).st_mode & 0o077:
                        out.append((e.line, "error", f"{v} is accessible by others (mode {oct(stat.S_IMODE(os.stat(path).st_mode))}); ssh will refuse it"))
    if config_path and os.path.exists(config_path):
        mode = os.stat(config_path).st_mode
        if mode & 0o022:
            out.append((0, "error", f"{config_path} is writable by group/others (mode {oct(stat.S_IMODE(mode))}); ssh refuses it"))
    return sorted(out, key=lambda x: x[0])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sshcfg-lint", description=__doc__)
    ap.add_argument("file", nargs="?", default=os.path.expanduser("~/.ssh/config"))
    ap.add_argument("--no-files", action="store_true", help="do not check key files on disk")
    ap.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    try:
        with open(a.file, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as ex:
        print(f"sshcfg-lint: {ex}", file=sys.stderr)
        return 2
    res = lint(text, a.file, not a.no_files)
    for line, lvl, msg in res:
        print(f"{a.file}:{line}: {lvl}: {msg}")
    bad = any(l == "error" or (a.strict and l == "warn") for _, l, _ in res)
    if not res:
        print("ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
