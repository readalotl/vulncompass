"""Scope judge — inspects Phoenix traces to verify the agent actually called
a VulnCompass tool rather than answering from internal knowledge.

A passing row has at least one span whose name matches a known VulnCompass tool.
"""

from __future__ import annotations

import time
from typing import Optional

VULNCOMPASS_TOOLS = {
    "assess_finding",
    "prioritize_findings",
    "detect_material_changes",
    "record_analyst_decision",
}


def check_tool_was_called(spans: list[dict]) -> dict:
    """Return a scope-judge result for a single trace's span list.

    Args:
        spans: List of span dicts from a Phoenix trace, each with at least a
               ``name`` key and optionally ``span_kind`` / ``attributes``.

    Returns:
        Dict with keys: score (0 or 1), tool_called (str | None), explanation.
    """
    for span in spans:
        name = span.get("name", "")
        if name in VULNCOMPASS_TOOLS:
            return {
                "score": 1,
                "tool_called": name,
                "explanation": f"Agent correctly called tool '{name}'.",
            }
        # Also check OpenInference attributes for tool name.
        attrs = span.get("attributes", {})
        tool_name = attrs.get("tool.name") or attrs.get("llm.function_call.name", "")
        if tool_name in VULNCOMPASS_TOOLS:
            return {
                "score": 1,
                "tool_called": tool_name,
                "explanation": f"Agent correctly called tool '{tool_name}'.",
            }

    return {
        "score": 0,
        "tool_called": None,
        "explanation": (
            "No VulnCompass tool call found in trace. "
            "Agent may have answered from internal knowledge."
        ),
    }


def fetch_spans_for_trace(
    trace_id: str,
    phoenix_host: str,
    project_name: str = "vulncompass-eval",
    *,
    retries: int = 3,
    retry_delay: float = 2.0,
) -> list[dict]:
    """Fetch all spans for a single trace_id from Phoenix.

    Retries a few times to allow the OTLP exporter to flush before we read.

    Args:
        trace_id:     Hex trace ID as returned by the OpenTelemetry tracer.
        phoenix_host: Base URL of the Phoenix instance (e.g. http://localhost:6006).
        project_name: Phoenix project name to scope the query.
        retries:      Number of fetch attempts if the dataframe comes back empty.
        retry_delay:  Seconds to wait between retries.

    Returns:
        List of span dicts with ``name`` and ``attributes`` keys populated from
        the Phoenix dataframe columns.
    """
    try:
        from phoenix.client import Client
        from phoenix.client.types.spans import SpanQuery

        client = Client(base_url=phoenix_host)

        for attempt in range(retries):
            df = client.spans.get_spans_dataframe(
                project_name=project_name,
                limit=500,
            )
            if df is None or df.empty:
                if attempt < retries - 1:
                    time.sleep(retry_delay)
                continue

            # Filter to this trace.
            if "context.trace_id" in df.columns:
                trace_df = df[df["context.trace_id"] == trace_id]
            else:
                trace_df = df

            if trace_df.empty and attempt < retries - 1:
                time.sleep(retry_delay)
                continue

            spans = []
            for _, row in trace_df.iterrows():
                span: dict = {}
                # Span name — stored in "name" column.
                span["name"] = str(row.get("name", ""))
                # Collect OpenInference attributes from columns prefixed with
                # "attributes." (Phoenix flattens them into individual columns).
                attrs: dict = {}
                for col in trace_df.columns:
                    if col.startswith("attributes."):
                        val = row.get(col)
                        if val is not None:
                            attrs[col[len("attributes."):]] = val
                span["attributes"] = attrs
                spans.append(span)
            return spans

    except Exception:  # noqa: BLE001
        pass

    return []


def run_scope(
    traces: list[list[dict]],
    *,
    trace_ids: Optional[list[Optional[str]]] = None,
    phoenix_host: str = "http://localhost:6006",
    project_name: str = "vulncompass-eval",
) -> list[dict]:
    """Score each trace in a batch.

    When ``trace_ids`` is supplied, spans are fetched live from Phoenix for any
    trace whose pre-loaded span list is empty.  This lets the caller pass empty
    lists as placeholders while still getting real scores.

    Args:
        traces:       One entry per dataset row, each a list of span dicts.
                      Pass ``[[] for _ in answers]`` as a placeholder when using
                      live fetching via ``trace_ids``.
        trace_ids:    Optional list of hex trace IDs aligned with ``traces``.
                      When a trace ID is provided and its span list is empty,
                      spans are fetched from Phoenix before scoring.
        phoenix_host: Base URL of the running Phoenix instance.
        project_name: Phoenix project to query.

    Returns:
        List of scope-judge result dicts (score, tool_called, explanation).
    """
    results = []
    for idx, spans in enumerate(traces):
        # If spans is empty and we have a trace_id, fetch from Phoenix.
        if not spans and trace_ids and idx < len(trace_ids):
            tid = trace_ids[idx]
            if tid:
                spans = fetch_spans_for_trace(
                    tid,
                    phoenix_host=phoenix_host,
                    project_name=project_name,
                )
        results.append(check_tool_was_called(spans))
    return results
