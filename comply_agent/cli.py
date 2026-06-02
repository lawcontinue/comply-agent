"""comply-agent CLI — AI Agent OWASP Compliance Scanner."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import Scanner
from .report import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        prog="comply-agent",
        description="AI Agent OWASP Agentic Top 10 Compliance Scanner",
    )
    sub = parser.add_subparsers(dest="command")

    # scan command
    scan_p = sub.add_parser("scan", help="Scan agent config/prompt for compliance issues")
    scan_p.add_argument("--prompt", "-p", help="Agent system prompt text")
    scan_p.add_argument("--prompt-file", help="File containing agent system prompt")
    scan_p.add_argument("--config", "-c", help="Agent configuration text")
    scan_p.add_argument("--config-file", help="File containing agent configuration")
    scan_p.add_argument("--tools", "-t", help="Tool definitions text")
    scan_p.add_argument("--tools-file", help="File containing tool definitions")
    scan_p.add_argument("--logs", "-l", help="Agent behavior logs text")
    scan_p.add_argument("--logs-file", help="File containing agent behavior logs")
    scan_p.add_argument("--format", "-f", choices=["terminal", "markdown", "json"],
                        default="terminal", help="Output format (default: terminal)")
    scan_p.add_argument("--output", "-o", help="Write report to file instead of stdout")
    scan_p.add_argument("--rules-dir", help="Custom rules directory")

    # list command
    sub.add_parser("rules", help="List all available rules")

    # version
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "version":
        from . import __version__
        print(f"comply-agent {__version__}")
        return

    if args.command == "rules":
        scanner = Scanner(getattr(args, "rules_dir", None))
        for r in scanner.rules:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(r.severity, "⚪")
            print(f"  {icon} {r.owasp_id}: {r.title} [{r.severity}] ({r.category})")
        print(f"\n  Total: {len(scanner.rules)} rules")
        return

    if args.command == "scan":
        # Load inputs
        prompt = args.prompt or _read_file(args.prompt_file)
        config = args.config or _read_file(args.config_file)
        tools = args.tools or _read_file(args.tools_file)
        logs = args.logs or _read_file(args.logs_file)

        if not any([prompt, config, tools, logs]):
            scan_p.error("At least one input required (--prompt, --config, --tools, --logs, or file variants)")

        scanner = Scanner(getattr(args, "rules_dir", None))
        result = scanner.scan(prompt=prompt, config=config, tools=tools, logs=logs)
        report = ReportGenerator(result)

        if args.format == "json":
            output = report.json()
        elif args.format == "markdown":
            output = report.markdown()
        else:
            output = report.terminal()

        if args.output:
            Path(args.output).write_text(output)
            print(f"Report written to {args.output}")
        else:
            print(output)

        sys.exit(1 if result.findings else 0)

    parser.print_help()


def _read_file(path: str | None) -> str | None:
    if path and Path(path).exists():
        return Path(path).read_text()
    return None


if __name__ == "__main__":
    main()
