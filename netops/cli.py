"""netops: analyse Cisco CLI captures and explain the problems.

    python -m netops samples/branch-sw01.txt
    python -m netops samples/branch-sw01.txt --lang ar --report report.md
    python -m netops samples/*.txt --no-ai
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .ai import explain
from .parsers import parse_capture
from .report import to_markdown
from .rules import analyze, health_score

console = Console()
COLOR = {"critical": "red", "warning": "yellow", "info": "cyan"}


def analyse_file(path: Path, args) -> int:
    cap = parse_capture(path.read_text(encoding="utf-8", errors="replace"))
    findings = analyze(cap)
    score = health_score(findings)
    colour = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    console.print(Panel.fit(
        f"[bold]{cap.hostname}[/]  ·  health [bold {colour}]{score}/100[/]  ·  "
        f"{len(cap.interfaces)} interfaces · {len(cap.ospf_neighbors)} OSPF neighbors · {len(cap.logs)} log lines",
        title=f"netops {__version__}", border_style=colour,
    ))

    if findings:
        table = Table(header_style="bold", show_lines=False)
        for col in ("Severity", "Finding", "Target", "Key evidence"):
            table.add_column(col)
        for f in findings:
            table.add_row(f"[{COLOR[f.severity]}]{f.severity.upper()}[/]", f.title, f.target, f.evidence[0])
        console.print(table)

    text, mode = explain(cap, findings, lang=args.lang, use_ai=not args.no_ai)
    console.print(Panel(Markdown(text), title="🤖 AI analysis" if mode == "ai" else "Summary (offline)", border_style="magenta"))

    if args.report:
        report_path = Path(args.report)
        if len(args.files) > 1:
            report_path = report_path.with_name(f"{report_path.stem}-{cap.hostname}{report_path.suffix}")
        report_path.write_text(to_markdown(cap, findings, text, mode), encoding="utf-8")
        console.print(f"[green]✔[/] report written to [bold]{report_path}[/]\n")

    return sum(f.severity == "critical" for f in findings)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netops", description="AI-assisted troubleshooting for Cisco CLI output")
    p.add_argument("files", nargs="+", type=Path, help="text file(s) with pasted show command output")
    p.add_argument("--lang", choices=["en", "ar"], default="en", help="language of the AI explanation")
    p.add_argument("--report", metavar="FILE.md", help="also write a Markdown report")
    p.add_argument("--no-ai", action="store_true", help="skip the Claude API call (offline summary)")
    p.add_argument("--version", action="version", version=f"netops {__version__}")
    args = p.parse_args(argv)

    criticals = 0
    for f in args.files:
        if not f.exists():
            console.print(f"[red]File not found:[/] {f}")
            return 2
        criticals += analyse_file(f, args)
    return 1 if criticals else 0


if __name__ == "__main__":
    sys.exit(main())
