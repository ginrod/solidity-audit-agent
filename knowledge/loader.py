"""
knowledge/loader.py

Parses the findings/ and triages/ markdown files into structured KnowledgeEntry
dicts used by the agent's reasoner node for few-shot calibration.

No LLM calls — purely deterministic regex/string parsing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

KNOWLEDGE_DIR = Path(__file__).parent


class TriageExample(TypedDict):
    title: str
    decision: str        # "VALID" | "FALSE POSITIVE" | "VALID (N/A)" | ...
    reasoning: str
    aa_severity: str     # AuditAgent's reported severity


class KnowledgeEntry(TypedDict):
    vuln_class: str          # "access_control", "reentrancy", etc.
    severity: str            # "Critical", "High", etc.
    description: str
    vulnerable_code: str     # fenced code block content
    recommendation: str
    triage_examples: list[TriageExample]
    false_positives: list[TriageExample]


# Maps finding filename prefix → vuln_class tag
_VULN_CLASS_MAP = {
    "01": "access_control",
    "02": "reentrancy",
    "03": "oracle_manipulation",
    "04": "front_running",
    "05": "integer_overflow",
}

# Maps triage filename → which vuln_class findings it covers (primary)
_TRIAGE_CLASS_MAP = {
    "triage-01": ["reentrancy", "access_control"],
    "triage-02": ["oracle_manipulation"],
    "triage-03": ["front_running"],
    "triage-04": ["integer_overflow"],
    "triage-05": ["access_control"],  # multisig — closest class
}


# ---------------------------------------------------------------------------
# Findings parser
# ---------------------------------------------------------------------------

def _parse_section(text: str, heading: str) -> str:
    """Extract content between ## heading and the next ## heading."""
    pattern = rf"##\s+{re.escape(heading)}\s*\n(.*?)(?=\n##\s|\Z)"
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _extract_code_block(section_text: str) -> str:
    """Extract the first fenced code block from a section."""
    m = re.search(r"```(?:solidity)?\n(.*?)```", section_text, re.DOTALL)
    return m.group(1).strip() if m else section_text.strip()


def _parse_severity(text: str) -> str:
    m = re.search(r"##\s+Severity\s*\n+(\w+)", text, re.IGNORECASE)
    return m.group(1).strip() if m else "Unknown"


def _parse_finding_file(path: Path, vuln_class: str) -> dict:
    text = path.read_text(encoding="utf-8")
    vuln_code_section = _parse_section(text, "Vulnerable Code")
    return {
        "vuln_class": vuln_class,
        "severity": _parse_severity(text),
        "description": _parse_section(text, "Description"),
        "vulnerable_code": _extract_code_block(vuln_code_section),
        "recommendation": _parse_section(text, "Recommendation"),
    }


# ---------------------------------------------------------------------------
# Triage parser
# ---------------------------------------------------------------------------

def _parse_triage_file(path: Path) -> list[TriageExample]:
    """
    Parse all findings from a triage markdown into TriageExample dicts.
    Triage format:
        ## Finding N — Severity: Title
        **Tool Severity:** X
        **Triage Decision:** Y
        <reasoning text>
    """
    text = path.read_text(encoding="utf-8")
    examples: list[TriageExample] = []

    # Split on "## Finding" boundaries
    blocks = re.split(r"(?=^##\s+Finding\s+\d+)", text, flags=re.MULTILINE)

    for block in blocks:
        if not re.match(r"^##\s+Finding\s+\d+", block.strip()):
            continue

        # Extract title from the heading line
        title_m = re.match(r"^##\s+Finding\s+\d+\s+[—–-]+\s*(.+)", block, re.MULTILINE)
        title = title_m.group(1).strip() if title_m else block.split("\n")[0].strip()

        # AuditAgent severity
        aa_sev_m = re.search(r"\*\*Tool Severity:\*\*\s*(.+)", block)
        aa_severity = aa_sev_m.group(1).strip() if aa_sev_m else "Unknown"

        # Triage decision (first line after the label)
        decision_m = re.search(r"\*\*Triage Decision:\*\*\s*(.+)", block)
        raw_decision = decision_m.group(1).strip() if decision_m else ""

        # Normalize decision to one of the canonical labels
        upper = raw_decision.upper()
        if "FALSE POSITIVE" in upper:
            decision = "FALSE POSITIVE"
        elif "VALID" in upper:
            decision = "VALID"
        else:
            decision = raw_decision

        # Reasoning: everything after the Triage Decision line
        reasoning = ""
        if decision_m:
            after = block[decision_m.end():]
            reasoning = after.strip()

        examples.append(
            TriageExample(
                title=title,
                decision=decision,
                reasoning=reasoning,
                aa_severity=aa_severity,
            )
        )

    return examples


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_knowledge_base() -> list[KnowledgeEntry]:
    """
    Load all findings and triage files, merge them by vuln_class, and return
    a list of KnowledgeEntry dicts ready for injection into LLM prompts.
    """
    findings_dir = KNOWLEDGE_DIR / "findings"
    triages_dir = KNOWLEDGE_DIR / "triages"

    # Parse findings
    entries: dict[str, KnowledgeEntry] = {}
    for finding_path in sorted(findings_dir.glob("*.md")):
        prefix = finding_path.stem[:2]
        vuln_class = _VULN_CLASS_MAP.get(prefix, "unknown")
        parsed = _parse_finding_file(finding_path, vuln_class)
        entries[vuln_class] = KnowledgeEntry(
            vuln_class=vuln_class,
            severity=parsed["severity"],
            description=parsed["description"],
            vulnerable_code=parsed["vulnerable_code"],
            recommendation=parsed["recommendation"],
            triage_examples=[],
            false_positives=[],
        )

    # Parse triages and attach to the matching entries
    for triage_path in sorted(triages_dir.glob("*.md")):
        examples = _parse_triage_file(triage_path)
        triage_key = triage_path.stem  # e.g. "triage-01"
        target_classes = _TRIAGE_CLASS_MAP.get(triage_key, [])

        for example in examples:
            for vuln_class in target_classes:
                if vuln_class not in entries:
                    continue
                if example["decision"] == "FALSE POSITIVE":
                    entries[vuln_class]["false_positives"].append(example)
                else:
                    entries[vuln_class]["triage_examples"].append(example)

    return list(entries.values())


def get_entry(vuln_class: str) -> KnowledgeEntry | None:
    """Return the KnowledgeEntry for a specific vulnerability class."""
    for entry in get_knowledge_base():
        if entry["vuln_class"] == vuln_class:
            return entry
    return None


def format_few_shot(entry: KnowledgeEntry, max_examples: int = 3) -> str:
    """
    Format a KnowledgeEntry as a compact few-shot block for LLM injection.
    Returns a string like:

        === REFERENCE: reentrancy ===
        Severity: High
        Pattern: [vulnerable code snippet]
        Known TRUE POSITIVE example:
          "[title]" — [reasoning summary]
        Known FALSE POSITIVE example:
          "[title]" — [reasoning summary]
    """
    lines = [
        f"=== REFERENCE: {entry['vuln_class']} ===",
        f"Severity: {entry['severity']}",
        f"Description: {entry['description'][:200]}...",
        "",
        "Vulnerable pattern:",
        "```solidity",
        entry["vulnerable_code"][:400],
        "```",
    ]

    if entry["triage_examples"]:
        lines.append("\nValidated TRUE POSITIVE examples (from AuditAgent scans):")
        for ex in entry["triage_examples"][:max_examples]:
            summary = ex["reasoning"][:150].replace("\n", " ")
            lines.append(f'  - "{ex["title"]}" → {summary}...')

    if entry["false_positives"]:
        lines.append("\nKnown FALSE POSITIVE patterns (do NOT report these):")
        for fp in entry["false_positives"]:
            summary = fp["reasoning"][:200].replace("\n", " ")
            lines.append(f'  - "{fp["title"]}" → {summary}...')

    return "\n".join(lines)
