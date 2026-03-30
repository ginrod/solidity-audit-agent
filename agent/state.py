from typing import TypedDict, Annotated
from dataclasses import dataclass, field
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


@dataclass
class Finding:
    severity: str          # Critical / High / Medium / Low / Informational
    title: str
    description: str
    vulnerable_code: str
    line: int | None
    impact: str
    recommendation: str
    false_positive: bool = False
    fp_reason: str = ""


class AgentState(TypedDict):
    contract_path: str
    contract_code: str
    functions: list[dict]           # extracted by loader: [{name, body, start_line}]
    candidates: list[str]           # vulnerability classes to analyze
    findings: list[Finding]
    false_positives: list[Finding]
    messages: Annotated[list[BaseMessage], add_messages]
    report_path: str
