from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import run_all
from .loader import ConfigError, discover, load_file
from .model import Finding, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
RESET = "\033[0m"


def _text(findings: list[Finding], files: int, color: bool) -> str:
    if not findings:
        return f"No findings in {files} config file(s)."
    lines = []
    for f in findings:
        tag = f"[{f.severity.name}]"
        if color:
            tag = COLORS[f.severity] + tag + RESET
        lines.append(f"{tag} {f.rule}  {f.file} :: {f.location}")
        lines.append(f"    {f.message}")
        if f.remediation:
            lines.append(f"    fix: {f.remediation}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = ", ".join(f"{n} {s.name.lower()}" for s, n in sorted(counts.items(), reverse=True) if n)
    lines.append(f"\n{len(findings)} finding(s) in {files} config file(s): {summary}")
    return "\n".join(lines)


def _sarif(findings: list[Finding]) -> dict:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
             Severity.LOW: "note", Severity.INFO: "note"}
    rules = sorted({f.rule for f in findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "agent-config-audit", "version": __version__,
                                "rules": [{"id": r} for r in rules]}},
            "results": [{
                "ruleId": f.rule,
                "level": level[f.severity],
                "message": {"text": f"{f.message} ({f.location})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}}}],
            } for f in findings],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent-config-audit",
        description="Static security audit of MCP server and AI agent permission configs.",
    )
    p.add_argument("paths", nargs="*", type=Path, default=[Path(".")],
                   help="config files or directories to scan (default: current directory)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--fail-on", default="high",
                   help="exit with code 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--include-disabled", action="store_true", help="also scan servers marked disabled")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as exc:
        p.error(str(exc))

    files = discover(args.paths)
    if not files:
        print("No MCP/agent config files found.", file=sys.stderr)
        return 0

    findings: list[Finding] = []
    errors = 0
    for path in files:
        try:
            findings += run_all(load_file(path), include_disabled=args.include_disabled)
        except ConfigError as exc:
            print(f"warning: {exc}", file=sys.stderr)
            errors += 1

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "sarif":
        print(json.dumps(_sarif(findings), indent=2))
    else:
        print(_text(findings, len(files) - errors, color=sys.stdout.isatty() and not args.no_color))

    if errors == len(files):
        return 2
    return 1 if any(f.severity >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
