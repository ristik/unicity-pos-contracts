#!/usr/bin/env python3
"""Disable-each-guard self-test for the P85 PR2 contracts.

For every entry of a mutation list it applies one source edit (a guard disabled or a formula
weakened) to a scratch copy of the repository, runs the named tests, and records whether at least
one of them failed. Usage:

    python3 script/p85-mutate.py mutations.json [--workers N] [--out results.json]

mutations.json is a list of objects:
    {"id": "...", "file": "src/p85/X.sol", "old": "<exact text>", "new": "<replacement>",
     "tests": "<forge --match-test regex of the test(s) that must fail>", "guard": "<description>"}

`old` must occur exactly once in `file`. The scratch copies live under /private/tmp/p85mut and are
deleted at the end. This is a developer tool; CI does not run it.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = "/private/tmp/p85mut"
FORGE = os.path.expanduser("~/.foundry/bin/forge")


def line_of(path, old):
    text = open(path).read()
    idx = text.index(old)
    return text.count("\n", 0, idx) + 1


def contract_of(path):
    return os.path.basename(path)[: -len(".sol")]


def test_error_map():
    """error selector reference -> test function names, from test/p85/*.t.sol"""
    refs = {}
    for name in sorted(os.listdir(os.path.join(ROOT, "test/p85"))):
        if not name.endswith(".t.sol"):
            continue
        text = open(os.path.join(ROOT, "test/p85", name)).read()
        for m in re.finditer(r"function (test\w+)\(.*?\n    \}\n", text, re.S):
            body = m.group(0)
            for e in re.finditer(r"(\w+)\.(\w+)\.selector", body):
                refs.setdefault((e.group(1), e.group(2)), set()).add(m.group(1))
    return refs


def generate():
    """One mutation per revert guard in src/p85: the condition is replaced by `block.chainid == 0 && (cond)`, an expression that is false in
    every test (a literal `false` trips the boolean-cst lint under deny_warnings)."""
    refs = test_error_map()
    muts = []
    for name in sorted(os.listdir(os.path.join(ROOT, "src/p85"))):
        if not name.endswith(".sol") or name in ("P85Types.sol", "IP85.sol"):
            continue
        rel = "src/p85/" + name
        text = open(os.path.join(ROOT, rel)).read()
        pattern = r"if \(([^;{}]+?)\) (?:revert (\w+)\(([^;]*?)\);|\{\s*revert (\w+)\(([^;]*?)\);\s*\})"
        for m in re.finditer(pattern, text, re.S):
            cond, err = m.group(1), m.group(2) or m.group(4)
            old = m.group(0)
            if text.count(old) != 1:
                # identical statements in one file: disambiguate with the preceding line
                start = text.rfind("\n", 0, m.start() - 1) + 1
                old = text[start : m.end()]
                if text.count(old) != 1:
                    continue
            contract = contract_of(name)
            tests = refs.get((contract, err)) or refs.get(("KeyLib", err)) or set()
            if not tests:
                for (c, e), t in refs.items():
                    if e == err and c in ("PolicyBounds", "FixedPolicy", "PosFactory"):
                        tests |= t
            line = text.count("\n", 0, m.start()) + 1
            muts.append(
                {
                    "id": "%s:%d:%s" % (name[:-4], line, err),
                    "file": rel,
                    "old": old,
                    "new": old.replace(
                        "if (" + cond + ")",
                        # pure code cannot read block.chainid: use an impossible uint16 comparison
                        "if ((" + cond + ") && p.penaltyBps > type(uint16).max)"
                        if name == "PolicyBounds.sol"
                        else "if (block.chainid == 0 && (" + cond + "))",
                        1,
                    ),
                    "tests": "^(" + "|".join(sorted(tests)) + ")$" if tests else "^$",
                    "guard": "revert %s" % err,
                    "no_test_named": not tests,
                }
            )
    return muts


def test_files():
    """test function name -> test file basename, for every *.t.sol under test/."""
    owner = {}
    for dirpath, _, names in os.walk(os.path.join(ROOT, "test")):
        for name in names:
            if not name.endswith(".t.sol"):
                continue
            text = open(os.path.join(dirpath, name)).read()
            for m in re.finditer(r"function ((?:test|invariant)\w*)\(", text):
                owner[m.group(1)] = name
            owner["__file__" + name] = name
    return owner


def skip_args(owner, tests_regex):
    """--skip filters for every test file that holds none of the named tests (faster rebuilds)."""
    wanted = set()
    for tok in re.findall(r"(?:test|invariant)\w*", tests_regex):
        if tok in owner:
            wanted.add(owner[tok])
    if not wanted:
        return []
    args = []
    for key, name in owner.items():
        if key.startswith("__file__") and name not in wanted:
            args += ["--skip", name]
    return args


def make_copy(worker):
    dest = os.path.join(SCRATCH, "w%d" % worker)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(
        ROOT,
        dest,
        ignore=shutil.ignore_patterns(".git", "broadcast", "out", "cache"),  # force a clean build in the copy
        symlinks=True,
    )
    return dest


OWNER = {}


def match_pattern(regex):
    """forge matches --match-test against `name()`, so an anchored `$` never matches."""
    if regex.endswith(")$"):
        return regex[:-2] + r")\("
    if regex.endswith("$"):
        return regex[:-1] + r"\("
    return regex


def run_one(dest, m):
    path = os.path.join(dest, m["file"])
    original = open(path).read()
    count = original.count(m["old"])
    if count != 1:
        return {"id": m["id"], "status": "BAD-MUTATION", "detail": "old text occurs %d times" % count}
    line = line_of(os.path.join(ROOT, m["file"]), m["old"])
    open(path, "w").write(original.replace(m["old"], m["new"]))
    try:
        proc = subprocess.run(
            [FORGE, "test", "--match-test", match_pattern(m["tests"])] + skip_args(OWNER, m["tests"]),
            cwd=dest,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        out = proc.stdout + proc.stderr
        failed = sorted(set(re.findall(r"^\[FAIL.*\]\s+(\w+)\(", out, re.M)))
        passed = sorted(set(re.findall(r"^\[PASS\]\s+(\w+)", out, re.M)))
        compile_error = "Compiler run failed" in out or "Error: " in out and not (failed or passed)
        if compile_error:
            status = "COMPILE-ERROR"
        elif failed:
            status = "CAUGHT"
        elif not passed:
            status = "NO-TEST-RAN"  # never reported as a survivor: the named tests did not run
        elif proc.returncode == 0:
            status = "SURVIVED"
        else:
            status = "ERROR"
        return {
            "id": m["id"],
            "file": m["file"],
            "line": line,
            "guard": m.get("guard", ""),
            "old": m["old"].strip().replace("\n", " "),
            "new": m["new"].strip().replace("\n", " "),
            "status": status,
            "failing": failed,
            "ran": len(passed) + len(failed),
            "detail": out[-900:] if status in ("COMPILE-ERROR", "ERROR", "NO-TEST-RAN") else "",
        }
    finally:
        open(path, "w").write(original)


def report(results_path):
    """Markdown table of a results file: guard, location, disabling edit, failing tests."""
    results = json.load(open(results_path))
    lines = [
        "# P85 PR2 guard self-test",
        "",
        "Generated by `script/p85-mutate.py --report`. Each row disables one guard (or weakens one",
        "formula) in a scratch copy of the repository and runs the named tests; `caught` means at",
        "least one of them failed. Line numbers refer to the source at the PR head.",
        "",
        "| # | Guard | Location | Edit | Failing tests | Result |",
        "|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(results, 1):
        edit = "`%s` → `%s`" % (
            r["old"].replace("|", "\\|")[:90],
            (r["new"].replace("|", "\\|") or "(removed)")[:90],
        )
        lines.append(
            "| %d | %s | `%s:%d` | %s | %s | %s |"
            % (
                i,
                r["guard"] or r["id"],
                r["file"],
                r["line"],
                edit,
                ", ".join("`%s`" % t for t in r["failing"]) or "none",
                r["status"].lower(),
            )
        )
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mutations", help="mutation list (JSON), or --generate to write one from src/p85")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--report", action="store_true", help="print a markdown table of a results file")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--out", default="mutation-results.json")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    if args.report:
        report(args.mutations)
        return
    if args.generate:
        muts = generate()
        json.dump(muts, open(args.mutations, "w"), indent=1)
        print("wrote %d mutations (%d without a named test)" % (len(muts), sum(1 for m in muts if m["no_test_named"])))
        return
    muts = json.load(open(args.mutations))
    if args.only:
        muts = [m for m in muts if re.search(args.only, m["id"])]
    OWNER.update(test_files())
    os.makedirs(SCRATCH, exist_ok=True)
    copies = [make_copy(i) for i in range(args.workers)]
    free = list(range(args.workers))
    lock = threading.Lock()
    results = []

    def job(m):
        with lock:
            w = free.pop()
        try:
            r = run_one(copies[w], m)
        finally:
            with lock:
                free.append(w)
        with lock:
            results.append(r)
            print("%-14s %s" % (r["status"], r["id"]), flush=True)
            if r["status"] not in ("CAUGHT", "SURVIVED"):
                print("    " + r.get("detail", "")[-400:].replace("\n", "\n    "), flush=True)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(job, muts))
    results.sort(key=lambda r: r["id"])
    json.dump(results, open(args.out, "w"), indent=1)
    shutil.rmtree(SCRATCH, ignore_errors=True)
    bad = [r for r in results if r["status"] != "CAUGHT"]
    print("%d mutations, %d caught, %d not caught" % (len(results), len(results) - len(bad), len(bad)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
