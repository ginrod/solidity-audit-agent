"""
agent/nodes/reporter.py

LangGraph node: generates the final Markdown audit report in Code4rena/Immunefi format.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from agent.state import AgentState, Finding

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]


def _severity_badge(severity: str) -> str:
    badges = {
        "Critical": "🔴 Critical",
        "High":     "🟠 High",
        "Medium":   "🟡 Medium",
        "Low":      "🔵 Low",
        "Informational": "⚪ Informational",
    }
    return badges.get(severity, severity)


def _render_finding(idx: int, f: Finding) -> str:
    line_ref = f"Line {f.line}" if f.line else "N/A"
    code_block = f"```solidity\n{f.vulnerable_code}\n```" if f.vulnerable_code else "_Not available_"
    return f"""### [{_severity_badge(f.severity)}] {idx}. {f.title}

**Location:** {line_ref}

**Description:**
{f.description}

**Vulnerable Code:**
{code_block}

**Impact:**
{f.impact}

**Recommendation:**
{f.recommendation}

---
"""


def write_report(state: AgentState) -> dict:
    contract_name = Path(state["contract_path"]).name
    findings = sorted(
        state["findings"],
        key=lambda f: _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else 99,
    )
    false_positives = state["false_positives"]

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_lines = [f"- **{sev}:** {n}" for sev, n in counts.items() if n > 0]
    summary_block = "\n".join(summary_lines) if summary_lines else "- No findings"

    sections = [
        f"# Specter Audit Report\n",
        f"**Contract:** `{contract_name}`  ",
        f"**Date:** {date.today().isoformat()}  ",
        f"**Total findings:** {len(findings)}  \n",
        f"## Executive Summary\n",
        summary_block,
        f"\n---\n",
        f"## Findings\n",
    ]

    if findings:
        for idx, f in enumerate(findings, start=1):
            sections.append(_render_finding(idx, f))
    else:
        sections.append("_No findings detected._\n")

    if false_positives:
        sections.append("## Discarded (False Positives)\n")
        for fp in false_positives:
            sections.append(f"- **{fp.title}** — {fp.fp_reason}\n")

    report = "\n".join(sections)
    Path(state["report_path"]).write_text(report, encoding="utf-8")
    return {}
