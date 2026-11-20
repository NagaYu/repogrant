"""Command-line interface: `repogrant check <repo>` and `repogrant defaults`.

Stateless core, no network, deterministic.
"""
from __future__ import annotations

import argparse
import sys

from .model import TOOL_VERSION
from .report import analyze, defaults_matrix, render_defaults_md, to_json


def _emit(text: str, out: str | None):
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repogrant",
        description="Compute the effective agent authority a repository grants, per tool, "
                    "under each tool's documented semantics.")
    p.add_argument("--version", action="version", version=f"repogrant {TOOL_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="analyze a repository tree and emit a JSON report")
    pc.add_argument("repo", help="path to the repository tree to analyze")
    pc.add_argument("--out", help="write report to this file instead of stdout")
    pc.add_argument("--name", help="override the target name recorded in the report")
    pc.add_argument("--strict", action="store_true",
                    help="exit non-zero (1) if any findings are reported")

    pd = sub.add_parser("defaults", help="emit the Part B tool-defaults matrix")
    pd.add_argument("--out", help="write to this file instead of stdout")
    pd.add_argument("--md", action="store_true", help="render as the Markdown audit document")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "check":
        import os
        if not os.path.isdir(args.repo):
            sys.stderr.write(f"repogrant: not a directory: {args.repo}\n")
            return 2
        report = analyze(args.repo, name=args.name)
        _emit(to_json(report), args.out)
        if args.strict and report["summary"]["total_findings"] > 0:
            return 1
        return 0
    if args.cmd == "defaults":
        matrix = defaults_matrix()
        text = render_defaults_md(matrix) if args.md else to_json(matrix)
        _emit(text, args.out)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
