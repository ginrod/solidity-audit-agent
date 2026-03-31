"""
agent/nodes/loader.py

LangGraph node: reads the Solidity contract and extracts individual functions
into structured dicts. No LLM calls — purely deterministic.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent.state import AgentState


def _extract_functions(code: str) -> list[dict]:
    """
    Extract top-level functions from Solidity source using bracket counting.
    Returns list of dicts: {name, visibility, modifiers, signature, body, start_line}.
    """
    functions = []
    lines = code.splitlines()

    # Regex for function declaration line
    fn_re = re.compile(
        r"\bfunction\s+(\w+)\s*\([^)]*\)"  # function name(params)
        r"((?:\s+(?:public|private|internal|external|pure|view|payable|virtual|override|\w+))*)"  # qualifiers
        r"\s*(?:returns\s*\([^)]*\))?\s*\{"  # optional returns + opening brace
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        m = fn_re.search(line)
        if not m:
            i += 1
            continue

        name = m.group(1)
        qualifiers = m.group(2).split() if m.group(2) else []
        visibility = next((q for q in qualifiers if q in {"public", "private", "internal", "external"}), "internal")
        modifiers = [q for q in qualifiers if q not in {"public", "private", "internal", "external", "pure", "view", "payable", "virtual", "override"}]
        start_line = i + 1  # 1-based

        # Collect the function body by counting braces
        depth = 0
        body_lines: list[str] = []
        j = i
        while j < len(lines):
            body_lines.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and j > i:
                break
            j += 1

        body = "\n".join(body_lines)
        functions.append({
            "name": name,
            "visibility": visibility,
            "modifiers": modifiers,
            "signature": line.strip(),
            "body": body,
            "start_line": start_line,
        })
        i = j + 1

    return functions


def load(state: AgentState) -> dict:
    path = Path(state["contract_path"])
    code = path.read_text(encoding="utf-8")
    functions = _extract_functions(code)
    return {"contract_code": code, "functions": functions}
