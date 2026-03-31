"""
agent/nodes/scanner.py

LangGraph node: runs all deterministic pattern detectors against the loaded
contract and populates state["candidates"] with detected hints.
"""
from agent.state import AgentState
import patterns.reentrancy as reentrancy
import patterns.access_control as access_control
import patterns.oracle_manipulation as oracle_manipulation
import patterns.front_running as front_running
import patterns.integer_overflow as integer_overflow

_DETECTORS = [
    reentrancy,
    access_control,
    oracle_manipulation,
    front_running,
    integer_overflow,
]


def scan(state: AgentState) -> dict:
    functions = state["functions"]
    code = state["contract_code"]
    candidates: list[str] = []

    for detector in _DETECTORS:
        hits = detector.detect(functions, code)
        candidates.extend(hits)

    return {"candidates": candidates}
