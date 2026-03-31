"""
agent/nodes/reasoner.py

LangGraph node: validates each candidate with the LLM using few-shot
examples from the knowledge base. Splits results into findings / false_positives.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from agent.state import AgentState, Finding
from knowledge.loader import format_few_shot, get_entry

_SYSTEM_PROMPT_PATH = Path(__file__).parent.parent.parent / "prompts" / "audit_system.txt"
_SYSTEM_TEMPLATE = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def _get_llm():
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o"), temperature=0)
    from langchain_anthropic import ChatAnthropic
    return ChatAnthropic(
        model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),  # type: ignore[call-arg]
        temperature=0,
    )


def _extract_json(text: str) -> dict:
    """Extract the first JSON object from LLM response text."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group())
    raise ValueError(f"No JSON found in LLM response: {text[:200]}")


def _vuln_class_from_candidate(candidate: str) -> str:
    """Parse 'vuln_class:hint' → 'vuln_class'."""
    return candidate.split(":")[0]


def reason(state: AgentState) -> dict:
    if not state["candidates"]:
        return {"findings": [], "false_positives": []}

    llm = _get_llm()
    findings: list[Finding] = []
    false_positives: list[Finding] = []

    for candidate in state["candidates"]:
        vuln_class = _vuln_class_from_candidate(candidate)
        entry = get_entry(vuln_class)

        # Build few-shot block
        few_shot = format_few_shot(entry) if entry else ""
        system_prompt = _SYSTEM_TEMPLATE.replace("{few_shot_block}", few_shot)

        human_content = (
            f"=== CONTRACT TO ANALYZE ===\n{state['contract_code']}\n\n"
            f"=== CANDIDATE PATTERN ===\n{candidate}"
        )

        messages = [SystemMessage(content=system_prompt), HumanMessage(content=human_content)]
        response = llm.invoke(messages)
        raw = response.content if hasattr(response, "content") else str(response)

        try:
            parsed = _extract_json(raw)
        except (ValueError, json.JSONDecodeError):
            # If we can't parse, treat as false positive to avoid hallucinations
            false_positives.append(Finding(
                severity="Unknown",
                title=candidate,
                description="LLM response could not be parsed",
                vulnerable_code="",
                line=None,
                impact="",
                recommendation="",
                false_positive=True,
                fp_reason="Unparseable LLM response",
            ))
            continue

        if parsed.get("is_finding"):
            findings.append(Finding(
                severity=parsed.get("severity", "Medium"),
                title=parsed.get("title", candidate),
                description=parsed.get("description", ""),
                vulnerable_code=parsed.get("vulnerable_code", ""),
                line=parsed.get("line"),
                impact=parsed.get("impact", ""),
                recommendation=parsed.get("recommendation", ""),
            ))
        else:
            false_positives.append(Finding(
                severity="N/A",
                title=candidate,
                description="",
                vulnerable_code="",
                line=None,
                impact="",
                recommendation="",
                false_positive=True,
                fp_reason=parsed.get("reason", "LLM determined not a finding"),
            ))

    return {"findings": findings, "false_positives": false_positives}
