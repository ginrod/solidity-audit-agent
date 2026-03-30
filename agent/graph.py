from langgraph.graph import StateGraph, END
from agent.state import AgentState


def ingest(state: AgentState) -> dict:
    """Load contract file and extract functions. Stub — implemented in nodes/loader.py."""
    return {}


def classify(state: AgentState) -> dict:
    """Identify candidate vulnerability classes. Stub — implemented in nodes/scanner.py."""
    return {}


def analyze(state: AgentState) -> dict:
    """LLM + few-shot: apply reference pattern per candidate. Stub — implemented in nodes/reasoner.py."""
    return {}


def validate(state: AgentState) -> dict:
    """Filter false positives via static reasoning. Stub — implemented in nodes/reasoner.py."""
    return {}


def report(state: AgentState) -> dict:
    """Generate Markdown report in Code4rena/Immunefi format. Stub — implemented in nodes/reporter.py."""
    return {}


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("ingest", ingest)
    graph.add_node("classify", classify)
    graph.add_node("analyze", analyze)
    graph.add_node("validate", validate)
    graph.add_node("report", report)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "classify")
    graph.add_edge("classify", "analyze")
    graph.add_edge("analyze", "validate")
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph.compile()


specter = build_graph()
