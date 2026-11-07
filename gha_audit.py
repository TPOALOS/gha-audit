#!/usr/bin/env python3
"""gha-audit - audit GitHub Actions workflow files for common security mistakes.

Offline and read-only. Uses line-based heuristics (the standard library has no
YAML parser), so it can miss things and can raise false positives; read
the limits section of the README. Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import os
import re
import sys

__version__ = "1.0.0"

SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^'\"\s#]+)")
RUN = re.compile(r"^(\s*)(-\s+)?run:\s*(.*?)\s*$")
BLOCK_MARKERS = {"|", ">", "|-", ">-", "|+", ">+"}
MUTABLE_REFS = {"main", "master", "latest", "develop", "dev", "trunk", "head"}
FIRST_PARTY = ("actions/", "github/")
# Attacker-controllable context values (issue/PR titles, branch names, comments ...).
UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|head_commit\.(?:message|author\.(?:email|name))"
    r"|commits[^}]*\.(?:message|author\.(?:email|name))|discussion\.(?:title|body))"
    r"|github\.head_ref)\s*\}\}")
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_")
CURL_PIPE = re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")


def strip_comment(line):
    return re.sub(r"(^|\s)#.*$", "", line)


def run_lines(lines):
    """Yield (lineno, text) for every line that belongs to a `run:` command."""
    i = 0
    while i < len(lines):
        m = RUN.match(strip_comment(lines[i]))
        if m:
            col = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
            rest = m.group(3)
            if rest in BLOCK_MARKERS:
                j = i + 1
                while j < len(lines):
                    raw = lines[j]
                    if raw.strip() and len(raw) - len(raw.lstrip()) <= col:
                        break
                    yield j + 1, raw
                    j += 1
                i = j
                continue
            if rest:
                yield i + 1, rest
        i += 1


def audit_text(text):
    """Return list of (severity, rule, lineno, message, fix)."""
    lines = text.splitlines()
    code = [strip_comment(l) for l in lines]
    joined = "\n".join(code)
    out = []
    add = lambda sev, rule, no, msg, fix: out.append((sev, rule, no, msg, fix))
    prt = re.search(r"(?m)^\s*(?:-\s*)?pull_request_target\b", joined) is not None
    pr_like = prt or re.search(r"(?m)^\s*(?:-\s*)?pull_request\b", joined) is not None

    for no, line in enumerate(code, 1):
        m = USES.match(line)
        if not m:
            continue
        target = m.group(1)
        if target.startswith("./") or target.startswith("docker://"):
            continue
        if "@" not in target:
            add("MEDIUM", "unpinned-action", no, "%s has no version" % target, "pin to a full commit SHA")
            continue
        name, ref = target.rsplit("@", 1)
        if SHA.match(ref):
            continue
        if ref.lower() in MUTABLE_REFS:
            add("HIGH", "unpinned-action", no, "%s@%s follows a mutable branch" % (name, ref),
                "pin to a full commit SHA")
        elif name.startswith(FIRST_PARTY):
            add("LOW", "unpinned-action", no, "%s@%s is a movable tag" % (name, ref), "pin to a full commit SHA")
        else:
            add("MEDIUM", "unpinned-action", no, "third-party %s@%s is a movable tag" % (name, ref),
                "pin to a full commit SHA and review the action")

    if prt:
        for no, line in enumerate(code, 1):
            if re.match(r"^\s*ref:", line) and HEAD_REF.search(line):
                add("HIGH", "pull-request-target-checkout", no,
                    "pull_request_target checks out untrusted pull request code",
                    "use pull_request, or never run PR code with secrets/write token")

    if re.search(r"(?m)^\s*permissions:\s*write-all\b", joined):
        no = next(i for i, l in enumerate(code, 1) if re.match(r"^\s*permissions:\s*write-all", l))
        add("HIGH", "write-all-permissions", no, "GITHUB_TOKEN gets write access to everything",
            "declare minimal permissions, e.g. `contents: read`")
    elif not re.search(r"(?m)^\s*permissions:", joined):
        add("MEDIUM", "missing-permissions", None,
            "no `permissions:` block; the token may default to broad write access",
            "add top-level `permissions: contents: read` and widen per job if needed")

    for no, text_line in run_lines(lines):
        if UNTRUSTED.search(text_line):
            add("HIGH", "script-injection", no,
                "untrusted value is expanded directly inside a shell command",
                "pass it through `env:` and use \"$VAR\" in the script")
        if re.search(r"\$\{\{\s*secrets\.", text_line):
            add("LOW", "secret-in-command", no, "secret expanded inline in a shell command",
                "pass it via `env:` instead")
        if CURL_PIPE.search(text_line):
            add("MEDIUM", "curl-pipe-shell", no, "downloads and executes a script without verification",
                "download, verify a checksum or signature, then run")

    if re.search(r"(?mi)^\s*ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['\"]?true", joined):
        no = next(i for i, l in enumerate(code, 1) if "ACTIONS_ALLOW_UNSECURE_COMMANDS" in l)
        add("HIGH", "unsecure-commands", no, "deprecated unsafe workflow commands are re-enabled",
            "remove it and use environment files")
    if pr_like:
        for no, line in enumerate(code, 1):
            if re.match(r"^\s*runs-on:.*self-hosted", line):
                add("MEDIUM", "self-hosted-on-pr", no,
                    "self-hosted runner used by a workflow triggered by pull requests",
                    "use GitHub-hosted runners for untrusted PRs")
    return out


SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def collect(paths):
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".yml", ".yaml")):
                        yield os.path.join(dirpath, f)
        else:
            yield p


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit GitHub Actions workflows (offline).")
    ap.add_argument("paths", nargs="*", default=[".github/workflows"], help="workflow files or folders")
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    files = list(collect(args.paths))
    if not files:
        print("gha-audit: no workflow files found", file=sys.stderr)
        return 2
    limit, count = SEV[args.min_severity], 0
    for path in files:
        try:
            with open(path, errors="replace") as fh:
                findings = audit_text(fh.read())
        except OSError as exc:
            print("gha-audit: %s" % exc, file=sys.stderr)
            return 2
        for sev, rule, no, msg, fix in sorted(findings, key=lambda f: (SEV[f[0]], f[2] or 0)):
            if SEV[sev] > limit:
                continue
            count += 1
            print("%-6s %-28s %s%s: %s\n         fix: %s" % (sev, rule, path, ":%d" % no if no else "", msg, fix))
    print("gha-audit: %d finding(s) in %d file(s)" % (count, len(files)), file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
