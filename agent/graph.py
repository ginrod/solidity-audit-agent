from langgraph.graph import StateGraph, END

from agent.state import AgentState
from agent.nodes.loader import load
from agent.nodes.scanner import scan
from agent.nodes.reasoner import reason
from agent.nodes.reporter import write_report


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("load", load)
    graph.add_node("scan", scan)
    graph.add_node("reason", reason)
    graph.add_node("write_report", write_report)

    graph.set_entry_point("load")
    graph.add_edge("load", "scan")
    graph.add_edge("scan", "reason")
    graph.add_edge("reason", "write_report")
    graph.add_edge("write_report", END)

    return graph.compile()


specter = build_graph()
