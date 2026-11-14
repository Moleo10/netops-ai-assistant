"""AI explanation layer (Claude API).

The model receives the *structured findings* (already verified by the rule engine) plus a
trimmed slice of the raw capture, and is asked to write an incident summary for an engineer:
ranked root causes, how the findings relate to each other, and an ordered action plan.

If no API key is configured, an offline summary is produced instead, so the tool always works.
"""

from __future__ import annotations

import json
import os

from .parsers import Capture
from .rules import Finding

DEFAULT_MODEL = os.environ.get("NETOPS_MODEL", "claude-sonnet-5-5")
MAX_RAW_CHARS = 6000

SYSTEM_PROMPT = """You are a senior network engineer (CCNP level) helping a NOC engineer triage a Cisco device.
You are given findings produced by a deterministic rule engine. Each finding is backed by evidence from the device.

Rules:
- Only use the evidence provided. Never invent interfaces, counters, neighbors or log lines.
- Look for relationships between findings (e.g. CRC errors + link flaps on the same port = one physical problem).
- Prioritise by user impact.
- Be concise and practical. Use Markdown.

Output exactly these sections:
## Summary
(2-3 sentences: overall state of the device and the most important problem)
## Root causes (ranked)
(numbered list; for each: the problem, the evidence it is based on, confidence high/medium/low)
## Action plan
(ordered checklist of concrete steps and IOS commands)
"""

LANG_HINT = {
    "en": "Write the answer in English.",
    "ar": "Write the answer in Arabic, but keep IOS commands, interface names and technical terms in English.",
}


def build_prompt(cap: Capture, findings: list[Finding], lang: str = "en") -> str:
    payload = {
        "device": cap.hostname,
        "commands_captured": cap.commands,
        "findings": [f.to_dict() for f in findings],
    }
    raw = cap.raw if len(cap.raw) <= MAX_RAW_CHARS else cap.raw[:MAX_RAW_CHARS] + "\n...[truncated]"
    return (
        f"{LANG_HINT.get(lang, LANG_HINT['en'])}\n\n"
        f"<findings>\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n</findings>\n\n"
        f"<raw_capture>\n{raw}\n</raw_capture>"
    )


def explain_with_claude(cap: Capture, findings: list[Finding], lang: str = "en", client=None) -> str:
    """Call the Claude API. `client` can be injected for testing."""
    if client is None:
        import anthropic  # lazy import: offline mode needs no SDK

        client = anthropic.Anthropic()
    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": build_prompt(cap, findings, lang)}],
    )
    return "".join(block.text for block in response.content if getattr(block, "type", "") == "text").strip()


def offline_summary(cap: Capture, findings: list[Finding]) -> str:
    """Deterministic fallback used when no API key is available."""
    if not findings:
        return f"## Summary\n{cap.hostname} looks healthy: no issues were detected in the captured output."
    crit = [f for f in findings if f.severity == "critical"]
    warn = [f for f in findings if f.severity == "warning"]
    lines = [
        "## Summary",
        f"{cap.hostname}: {len(crit)} critical and {len(warn)} warning findings. "
        f"Most urgent: **{findings[0].title}** on {findings[0].target}.",
        "",
        "## Action plan",
    ]
    step = 1
    for f in findings:
        if f.severity == "info":
            continue
        lines.append(f"{step}. **{f.title}** ({f.target}): {f.next_steps[0] if f.next_steps else 'investigate'}")
        step += 1
    lines.append("\n_Offline mode: set `ANTHROPIC_API_KEY` for an AI root-cause analysis that correlates the findings._")
    return "\n".join(lines)


def explain(cap: Capture, findings: list[Finding], lang: str = "en", use_ai: bool = True) -> tuple[str, str]:
    """Return (text, mode) where mode is 'ai' or 'offline'."""
    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return explain_with_claude(cap, findings, lang), "ai"
        except Exception as exc:  # network/SDK problems must not break the report
            return offline_summary(cap, findings) + f"\n\n_AI call failed ({type(exc).__name__}); showing offline summary._", "offline"
    return offline_summary(cap, findings), "offline"
