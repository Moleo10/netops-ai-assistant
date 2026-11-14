"""Markdown report generation."""

from __future__ import annotations

from datetime import datetime

from .parsers import Capture
from .rules import Finding, health_score

ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}


def to_markdown(cap: Capture, findings: list[Finding], explanation: str, mode: str) -> str:
    score = health_score(findings)
    out = [
        f"# NetOps report: {cap.hostname}",
        "",
        f"_Generated {datetime.now():%Y-%m-%d %H:%M} · analysis mode: {mode}_",
        "",
        "| Health score | Critical | Warning | Info | Interfaces parsed | OSPF neighbors | Log lines |",
        "|:-:|:-:|:-:|:-:|:-:|:-:|:-:|",
        f"| **{score}/100** | {sum(f.severity == 'critical' for f in findings)} | "
        f"{sum(f.severity == 'warning' for f in findings)} | {sum(f.severity == 'info' for f in findings)} | "
        f"{len(cap.interfaces)} | {len(cap.ospf_neighbors)} | {len(cap.logs)} |",
        "",
        explanation,
        "",
        "---",
        "",
        "# Findings (evidence)",
    ]
    for f in findings:
        out += [
            "",
            f"### {ICON[f.severity]} {f.title}: `{f.target}`",
            "",
            "**Evidence**",
            *[f"- {e}" for e in f.evidence],
            "",
            f"**Likely cause:** {f.likely_cause}",
            "",
            "**Next steps**",
            "```",
            *f.next_steps,
            "```",
        ]
    return "\n".join(out) + "\n"
