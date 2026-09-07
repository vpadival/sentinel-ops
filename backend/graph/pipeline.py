"""
graph/pipeline.py
──────────────────
Defines the LangGraph StateGraph that wires all agents together.

Phase 7 fix: Lazy initialization via get_graph(). The graph and Omium SDK
are initialized on first call, not at import time.

Graph topology:
  START → supervisor → scout → analyst ─┬─ confidence OK → reporter → END
                                         └─ low confidence → scout (loop)
"""

from __future__ import annotations
import threading
from typing import Any

from langgraph.graph import StateGraph, END  # type: ignore[import-untyped]

from backend.core.state import SentinelState, JobStatus
from backend.agents import supervisor_node, scout_node, analyst_node, reporter_node

CONFIDENCE_THRESHOLD = 0.6
MAX_LOOPS = 3

# ── Lazy singleton ─────────────────────────────────────────────────────────
_graph: Any = None
_graph_lock = threading.Lock()


def route_after_analyst(state: SentinelState) -> str:
    """
    Conditional edge: decides whether to loop back to Scout or proceed to Reporter.
    Called by LangGraph after every `analyst` node execution.
    """
    context    = state.get("context", {})
    loop_count = state.get("loop_count", 0)
    confidence = context.get("confidence", 1.0)
    status     = state.get("job_status")

    if status == JobStatus.FAILED:
        return "reporter"

    if confidence < CONFIDENCE_THRESHOLD and loop_count < MAX_LOOPS:
        return "scout"

    return "reporter"


def route_after_supervisor(state: SentinelState) -> str:
    """Stop immediately when the supervisor rejects the input."""
    return END if state.get("job_status") == JobStatus.FAILED else "scout"


def _build_graph() -> Any:
    """
    Constructs and compiles the Sentinel-Ops LangGraph pipeline.
    Returns a CompiledStateGraph behind the existing dynamic graph interface.
    """
    graph = StateGraph(SentinelState)

    # ── Register nodes ────────────────────────────────────────────────────
    # LangGraph's unused cache-policy overloads contain unresolved type parameters.
    # Suppress only that upstream member diagnostic, retaining argument checks.
    graph.add_node("supervisor", supervisor_node)  # pyright: ignore[reportUnknownMemberType]
    graph.add_node("scout",      scout_node)  # pyright: ignore[reportUnknownMemberType]
    graph.add_node("analyst",    analyst_node)  # pyright: ignore[reportUnknownMemberType]
    graph.add_node("reporter",   reporter_node)  # pyright: ignore[reportUnknownMemberType]

    # ── Wire edges ────────────────────────────────────────────────────────
    graph.set_entry_point("supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {END: END, "scout": "scout"},
    )
    graph.add_edge("scout",      "analyst")

    graph.add_conditional_edges(
        "analyst",
        route_after_analyst,
        {
            "scout":    "scout",
            "reporter": "reporter",
        },
    )

    graph.add_edge("reporter", END)

    # The optional checkpointer/cache parameters have the same upstream typing gap.
    return graph.compile()  # pyright: ignore[reportUnknownMemberType]


def get_graph() -> Any:
    """
    Lazy singleton — initializes Omium and builds the graph on first call.
    Thread-safe via lock.
    """
    global _graph
    if _graph is not None:
        return _graph

    with _graph_lock:
        if _graph is not None:
            return _graph

        # Initialize Omium before compiling the graph so it can instrument nodes
        from backend.core.omium import init_omium
        init_omium()

        _graph = _build_graph()
        return _graph


# Backwards compatibility — existing code imports `sentinel_graph` directly.
# This is now a lazy proxy; attribute access triggers initialization.
class _LazyGraph:
    """Proxy that defers graph construction until first use."""
    def __getattr__(self, name: str) -> Any:
        return getattr(get_graph(), name)

sentinel_graph = _LazyGraph()
