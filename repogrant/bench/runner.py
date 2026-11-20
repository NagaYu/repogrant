"""Dev-bench runner + Gate 1 self-scoring.

Scores repogrant against the ratified Gate 1 bars:
  - per-class recall  >= 0.90 (R1,R2,R4,R5) / >= 0.80 (R3,R6)
  - clean-repo false-positive rate <= 0.02
  - zero silent drops (every present-but-unparsed surface is in not_judgeable)
  - byte-identical determinism across repeated runs (and path-independence)

Run:  python3 bench/runner.py
Exit code 0 only if every Gate 1 bar passes.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PKG_ROOT)

from repogrant.report import analyze, to_json  # noqa: E402

REPOS = os.path.join(HERE, "repos")
VCS_MARKER = ".repogrant-bench-vcs"
CHECKS = ["R1", "R2", "R3", "R4", "R5", "R6"]
RECALL_BAR = {"R1": 0.90, "R2": 0.90, "R4": 0.90, "R5": 0.90, "R3": 0.80, "R6": 0.80}


def _materialize(repo_rel: str, dest_parent: str) -> str:
    """Copy a fixture to dest_parent/<basename>, turning the vcs marker into a real .git."""
    src = os.path.join(REPOS, repo_rel)
    dest = os.path.join(dest_parent, os.path.basename(repo_rel))
    shutil.copytree(src, dest)
    marker = os.path.join(dest, VCS_MARKER)
    if os.path.isfile(marker):
        os.remove(marker)
        os.makedirs(os.path.join(dest, ".git"))
        with open(os.path.join(dest, ".git", "HEAD"), "w") as fh:
            fh.write("ref: refs/heads/main\n")
    return dest


def _search_blob(finding: dict) -> str:
    parts = [finding.get("title", ""), finding.get("detail", "")]
    for e in finding.get("evidence", []):
        parts.append(e.get("locator", ""))
        parts.append(e.get("file", ""))
        parts.append(e.get("excerpt", ""))
    return " | ".join(parts)


def _matches(finding: dict, label: dict) -> bool:
    if finding["check"] != label["check"]:
        return False
    if label["tool"]:
        ftool = finding.get("tool", "")
        ftools = finding.get("tools", [])
        if ftool != label["tool"] and label["tool"] not in ftools:
            return False
    return label["match"] in _search_blob(finding)


def _silent_drops(report: dict) -> list:
    drops = []
    nj_files = {x.get("file") for x in report["not_judgeable"] if x.get("kind") == "parse-problem"}
    for tool, tdata in report["tools"].items():
        for s in tdata["surfaces"]:
            if s["present"] and not s["parsed"]:
                # a present-but-unparsed surface must be accounted for
                is_problem = s["file"] in nj_files
                # ignored-by-design surfaces (e.g. plain .md in .cursor/rules) carry a note
                has_note = bool(s.get("note"))
                if not is_problem and not has_note:
                    drops.append(f"{tool}:{s['file']}")
    return drops


def run():
    expected = json.load(open(os.path.join(HERE, "expected.json")))
    scratch = tempfile.mkdtemp(prefix="repogrant_bench_")
    scratch2 = tempfile.mkdtemp(prefix="repogrant_bench2_")
    det_failures = []
    silent_drops = []

    # ---- determinism + silent drops across ALL fixtures ----
    all_repos = list(expected["clean"]) + list(expected["mutations"].keys()) + list(expected["malformed"].keys())
    reports = {}
    for rel in all_repos:
        d1 = _materialize(rel, os.path.join(scratch, rel.replace("/", "_")))
        r1 = to_json(analyze(d1))
        r2 = to_json(analyze(d1))
        if r1 != r2:
            det_failures.append(f"{rel}: repeated run differs")
        # path independence: same basename, different parent
        d2 = _materialize(rel, os.path.join(scratch2, rel.replace("/", "_")))
        r3 = to_json(analyze(d2))
        if r1 != r3:
            det_failures.append(f"{rel}: path-dependent output")
        rep = json.loads(r1)
        reports[rel] = rep
        silent_drops += [f"{rel} -> {d}" for d in _silent_drops(rep)]

    # ---- clean-repo false positives ----
    clean_fp_pairs = 0
    clean_total_pairs = len(expected["clean"]) * len(CHECKS)
    clean_detail = {}
    for rel in expected["clean"]:
        rep = reports[rel]
        by_check = {c: 0 for c in CHECKS}
        for f in rep["findings"]:
            by_check[f["check"]] = by_check.get(f["check"], 0) + 1
        fp_here = {c: n for c, n in by_check.items() if n}
        clean_detail[rel] = {"total_findings": rep["summary"]["total_findings"], "by_check": fp_here}
        clean_fp_pairs += sum(1 for c in CHECKS if by_check[c] > 0)
    fp_rate = clean_fp_pairs / clean_total_pairs if clean_total_pairs else 0.0

    # ---- recall per class ----
    planted = {c: 0 for c in CHECKS}
    hit = {c: 0 for c in CHECKS}
    misses = []
    for rel, labels in expected["mutations"].items():
        rep = reports[rel]
        findings = rep["findings"]
        for label in labels:
            planted[label["check"]] += 1
            if any(_matches(f, label) for f in findings):
                hit[label["check"]] += 1
            else:
                misses.append(f"{rel}: MISS {label['check']} tool={label['tool'] or '-'} match={label['match']!r}")

    # ---- malformed -> not-judgeable ----
    malformed_ok = True
    malformed_detail = []
    for rel, files in expected["malformed"].items():
        rep = reports[rel]
        nj_files = {x.get("file") for x in rep["not_judgeable"] if x.get("kind") == "parse-problem"}
        for fpath in files:
            present = fpath in nj_files
            malformed_detail.append(f"{rel}:{fpath} -> {'not-judgeable OK' if present else 'MISSING (silent drop!)'}")
            if not present:
                malformed_ok = False

    shutil.rmtree(scratch, ignore_errors=True)
    shutil.rmtree(scratch2, ignore_errors=True)

    # ---- scorecard ----
    print("=" * 70)
    print("RepoGrant dev bench — Gate 1 self-scoring")
    print("=" * 70)
    print(f"\nFixtures: {len(expected['clean'])} clean, "
          f"{len(expected['mutations'])} mutation, {len(expected['malformed'])} malformed\n")

    print("Per-class recall:")
    recall_pass = True
    recall_summary = {}
    for c in CHECKS:
        p, h = planted[c], hit[c]
        r = (h / p) if p else 1.0
        bar = RECALL_BAR[c]
        ok = r >= bar
        recall_pass = recall_pass and ok
        recall_summary[c] = {"planted": p, "hit": h, "recall": round(r, 3), "bar": bar, "pass": ok}
        print(f"  {c}: {h}/{p} = {r:.2f}  (bar {bar:.2f})  {'PASS' if ok else 'FAIL'}")
    if misses:
        print("\n  Misses:")
        for m in misses:
            print(f"    - {m}")

    print(f"\nClean-repo false positives: {clean_fp_pairs}/{clean_total_pairs} "
          f"(repo,check) pairs = FP rate {fp_rate:.4f}  (bar <= 0.02)  "
          f"{'PASS' if fp_rate <= 0.02 else 'FAIL'}")
    for rel, det in clean_detail.items():
        flag = "" if det["total_findings"] == 0 else f"  <-- {det['by_check']}"
        print(f"    {rel}: {det['total_findings']} findings{flag}")

    print(f"\nZero silent drops: {'PASS' if not silent_drops else 'FAIL'}")
    for d in silent_drops:
        print(f"    - DROP {d}")
    print("  Malformed-surface accounting:")
    for d in malformed_detail:
        print(f"    - {d}")

    print(f"\nByte-identical determinism (repeat + path-independent): "
          f"{'PASS' if not det_failures else 'FAIL'}")
    for d in det_failures:
        print(f"    - {d}")

    fp_pass = fp_rate <= 0.02
    drop_pass = (not silent_drops) and malformed_ok
    det_pass = not det_failures
    overall = recall_pass and fp_pass and drop_pass and det_pass

    print("\n" + "=" * 70)
    print("GATE 1 BARS:")
    print(f"  recall             : {'PASS' if recall_pass else 'FAIL'}")
    print(f"  clean FP <= 0.02   : {'PASS' if fp_pass else 'FAIL'}")
    print(f"  zero silent drops  : {'PASS' if drop_pass else 'FAIL'}")
    print(f"  determinism        : {'PASS' if det_pass else 'FAIL'}")
    print(f"\nGATE 1: {'GO (PASS)' if overall else 'FAIL'}")
    print("=" * 70)

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(run())
