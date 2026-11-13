"""VulnCompassAgent — LangGraph ReAct agent wired to the VulnCompass MCP server.

Launches the server as a subprocess over stdio using the fastmcp Client and
exposes each MCP tool as a flat-parameter LangChain @tool so that ChatOllama's
native bind_tools() wire format works correctly. The tool functions assemble the
nested argument object the MCP server expects and call it synchronously.

Every LLM call and tool invocation is traced automatically by the OpenInference
LangChain instrumentor that run_experiment.py activates before importing this
module.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
from pathlib import Path
from typing import Any, Literal, Optional

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

# Holds the shared fastmcp Client for the duration of one agent.invoke() call
# so that assess_finding and record_analyst_decision share one server process
# (and therefore one SQLite connection) rather than spawning a new subprocess
# per tool call.
_mcp_client: contextvars.ContextVar[Client | None] = contextvars.ContextVar(
    "_mcp_client", default=None
)

# ── Paths ─────────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROMPT_PATH = Path(__file__).parent / "prompts" / "v1.txt"

# ── MCP server command ────────────────────────────────────────────────────────
# Resolve uv from PATH at import time so the subprocess works on any machine
# (local dev, CI runners, containers) without hardcoding an absolute path.
# Override with UV_BIN env var if the binary lives somewhere outside PATH.
import shutil as _shutil
_UV = os.environ.get("UV_BIN") or _shutil.which("uv") or "uv"
_SERVER_ARGS = ["run", "python", "-m", "vulncompass.app"]


def _transport() -> StdioTransport:
    # Suppress the fastmcp startup banner — it writes to stdout, which is the
    # MCP stdio pipe, and corrupts the JSON-RPC handshake on non-TTY systems
    # (CI runners, containers, any environment where stdout is a pipe).
    env = {**os.environ, "FASTMCP_SHOW_SERVER_BANNER": "false"}
    return StdioTransport(command=_UV, args=_SERVER_ARGS, cwd=str(_REPO_ROOT), env=env)


def _load_system_prompt() -> str:
    if _PROMPT_PATH.exists():
        return _PROMPT_PATH.read_text().strip()
    return (
        "You are VulnCompass, a software supply chain vulnerability management assistant. "
        "You have four tools: assess_finding, prioritize_findings, detect_material_changes, "
        "and record_analyst_decision. Always call the relevant tool — never answer from "
        "internal knowledge when a tool is available. Present results clearly."
    )


# ── MCP call helper ───────────────────────────────────────────────────────────

async def _call_tool_on_client(
    client: Client, tool_name: str, arguments: dict[str, Any]
) -> str:
    result = await client.call_tool(tool_name, arguments)
    # fastmcp 4.x: CallToolResult.content is a list of TextContent objects.
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict):
            parts.append(item.get("text", json.dumps(item)))
        else:
            parts.append(str(item))
    return "\n".join(parts)


async def _call_mcp_async(tool_name: str, arguments: dict[str, Any]) -> str:
    client = _mcp_client.get()
    if client is not None:
        # Reuse the shared client opened by invoke() — same server process,
        # same SQLite connection, so assess → record_decision works correctly.
        return await _call_tool_on_client(client, tool_name, arguments)
    # Fallback: open a one-shot client (used if called outside invoke()).
    async with Client(_transport()) as c:
        return await _call_tool_on_client(c, tool_name, arguments)


# The event loop running the shared MCP client (set by invoke()).
_mcp_loop: contextvars.ContextVar[asyncio.AbstractEventLoop | None] = (
    contextvars.ContextVar("_mcp_loop", default=None)
)


def _call_mcp(tool_name: str, arguments: dict[str, Any]) -> str:
    """Synchronous bridge safe to call from any thread, including LangGraph's
    ThreadPoolExecutor workers which already run inside an async context.

    When a shared client is active (inside invoke()), schedules the coroutine
    on the outer event loop so the client is called from its own thread.
    MCP tool errors are returned as plain text so the LLM can relay them.
    """
    try:
        loop = _mcp_loop.get()
        if loop is not None:
            # We are on a worker thread; submit the coroutine to the event loop
            # running on the main thread and block until it completes.
            import concurrent.futures
            future: concurrent.futures.Future[str] = asyncio.run_coroutine_threadsafe(
                _call_mcp_async(tool_name, arguments), loop
            )
            return future.result()
        # No shared client — spin up a fresh event loop (fallback / standalone).
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=1) as pool:
            f = pool.submit(asyncio.run, _call_mcp_async(tool_name, arguments))
            return f.result()
    except Exception as exc:  # noqa: BLE001
        return f"Error: {exc}"


# ── Flat-parameter LangChain tools ───────────────────────────────────────────
# Each function mirrors the VulnCompass tool's fields as flat typed parameters.
# bind_tools() uses the function's type annotations to build the JSON schema
# that the LLM sees — no nested objects, no prompt-embedded schema blobs.
# The function body assembles the nested dict the MCP server expects.

@tool
def assess_finding(
    finding_id: str,
    source_vendor: str,
    source_finding_id: str,
    cve_id: str,
    asset_id: str,
    vendor_severity: Optional[str] = None,
    vendor_risk_score: Optional[float] = None,
    vendor_priority: Optional[str] = None,
    applicability: Literal[
        "confirmed_affected", "likely_affected", "unknown", "confirmed_not_affected"
    ] = "unknown",
    internet_exposure: Literal["public", "internal", "isolated", "unknown"] = "unknown",
    mission_criticality: Literal["high", "moderate", "low", "unknown"] = "unknown",
    compensating_controls: Literal["present", "absent", "unknown"] = "unknown",
    mode: Literal["fixture", "cached", "live"] = "fixture",
) -> str:
    """Create a cited, deterministic assessment for a single vulnerability finding.

    Required: finding_id, source_vendor, source_finding_id, cve_id (CVE-YYYY-NNNN
    format), asset_id. Returns recommendation, confidence, rationale, and
    evidence from CVE Program, NVD, CISA KEV, Vulnrichment, and Nuclei.
    Status is always PENDING_REVIEW until record_analyst_decision is called.
    """
    finding: dict[str, Any] = {
        "finding_id": finding_id,
        "source_vendor": source_vendor,
        "source_finding_id": source_finding_id,
        "cve_id": cve_id,
        "asset_id": asset_id,
        "applicability": applicability,
        "internet_exposure": internet_exposure,
        "mission_criticality": mission_criticality,
        "compensating_controls": compensating_controls,
    }
    if vendor_severity is not None:
        finding["vendor_severity"] = vendor_severity
    if vendor_risk_score is not None:
        finding["vendor_risk_score"] = vendor_risk_score
    if vendor_priority is not None:
        finding["vendor_priority"] = vendor_priority
    return _call_mcp("assess_finding", {"finding": finding, "mode": mode})


@tool
def prioritize_findings(
    csv_text: str,
    mode: Literal["fixture", "cached", "live"] = "fixture",
    limit: int = 20,
) -> str:
    """Rank a list of vulnerability findings into an analyst review queue.

    Pass the findings as a CSV string with a header row. Required columns:
    finding_id, source_vendor, source_finding_id, cve_id, asset_id.
    Optional columns: vendor_severity, vendor_risk_score, vendor_priority,
    applicability, internet_exposure, mission_criticality, compensating_controls.
    Returns a ranked list with recommendation, confidence, and queue reason
    for each finding.
    """
    return _call_mcp(
        "prioritize_findings",
        {"request": {"csv_text": csv_text, "mode": mode, "limit": limit}},
    )


@tool
def detect_material_changes(
    cve_id: str,
    previous_kev_listed: bool,
    current_kev_listed: bool,
    previous_nvd_cvss_vector: Optional[str] = None,
    previous_nvd_status: Optional[str] = None,
    current_nvd_cvss_vector: Optional[str] = None,
    current_nvd_status: Optional[str] = None,
    previous_retrieved_at: str = "2000-01-01T00:00:00Z",
    current_retrieved_at: str = "2000-01-02T00:00:00Z",
    previous_ssvc_exploitation: Optional[str] = None,
    current_ssvc_exploitation: Optional[str] = None,
) -> str:
    """Compare two public evidence snapshots for a CVE and report material changes.

    Supply key fields from both the previous and current snapshot. Returns
    material_change_detected (bool), requires_analyst_rereview (bool), and
    a list of changed fields with old/new values and the policy rule triggered.
    """
    def _snapshot(
        kev_listed: bool,
        cvss_vector: Optional[str],
        nvd_status: Optional[str],
        ssvc_exploitation: Optional[str],
        retrieved_at: str,
    ) -> dict:
        snap: dict[str, Any] = {
            "cve_id": cve_id,
            "mode": "fixture",
            "retrieved_at": retrieved_at,
            "kev": {"listed": kev_listed},
        }
        if cvss_vector or nvd_status:
            snap["nvd"] = {}
            if cvss_vector:
                snap["nvd"]["cvss"] = {"vector": cvss_vector}
            if nvd_status:
                snap["nvd"]["status"] = nvd_status
        if ssvc_exploitation:
            snap["vulnrichment"] = {
                "ssvc": {"options": [{"Exploitation": ssvc_exploitation}]}
            }
        return snap

    return _call_mcp(
        "detect_material_changes",
        {
            "request": {
                "cve_id": cve_id,
                "previous_snapshot": _snapshot(
                    previous_kev_listed,
                    previous_nvd_cvss_vector,
                    previous_nvd_status,
                    previous_ssvc_exploitation,
                    previous_retrieved_at,
                ),
                "current_snapshot": _snapshot(
                    current_kev_listed,
                    current_nvd_cvss_vector,
                    current_nvd_status,
                    current_ssvc_exploitation,
                    current_retrieved_at,
                ),
                "mode": "fixture",
            }
        },
    )


@tool
def record_analyst_decision(
    finding_id: str,
    action: Literal["approve", "modify", "reject", "defer", "request_investigation"],
    rationale: str,
    analyst_id: Optional[str] = None,
    modified_recommendation: Optional[
        Literal[
            "immediate_review",
            "accelerated_remediation",
            "routine_remediation",
            "investigate_applicability",
            "proposed_closure",
        ]
    ] = None,
) -> str:
    """Record a permanent analyst decision for a previously assessed finding.

    Required: finding_id (must have been assessed first), action, rationale.
    Use action='modify' together with modified_recommendation to override the
    VulnCompass recommendation. Returns the full decision record with
    review_status=DECIDED and a frozen evidence snapshot.
    """
    decision: dict[str, Any] = {
        "finding_id": finding_id,
        "action": action,
        "rationale": rationale,
    }
    if analyst_id is not None:
        decision["analyst_id"] = analyst_id
    if modified_recommendation is not None:
        decision["modified_recommendation"] = modified_recommendation
    return _call_mcp("record_analyst_decision", {"decision": decision})


# ── Tools list exposed to the agent ──────────────────────────────────────────

VULNCOMPASS_TOOLS = [
    assess_finding,
    prioritize_findings,
    detect_material_changes,
    record_analyst_decision,
]


# ── LLM factory ──────────────────────────────────────────────────────────────

def _build_llm(model: str):
    """Return a LangChain chat model with tools bound.

    Prefix the model name with "openai:" to force ChatOpenAI, otherwise
    ChatOllama is used (no API key required).

    Examples:
        "llama3.1:8b"          → ChatOllama(model="llama3.1:8b")
        "openai:gpt-4o-mini"   → ChatOpenAI(model="gpt-4o-mini")
    """
    if model.startswith("openai:"):
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=model[len("openai:"):], temperature=0)
    from langchain_ollama import ChatOllama
    return ChatOllama(model=model, temperature=0)


# ── Agent ─────────────────────────────────────────────────────────────────────

class VulnCompassAgent:
    """Synchronous wrapper around a LangGraph ReAct agent connected to VulnCompass MCP."""

    def __init__(self, model: str = "llama3.1:8b") -> None:
        self._model_name = model
        self._agent = None

    def _ensure_built(self) -> None:
        if self._agent is not None:
            return
        llm = _build_llm(self._model_name)
        system_prompt = _load_system_prompt()
        self._agent = create_react_agent(
            llm,
            VULNCOMPASS_TOOLS,
            prompt=system_prompt,
        )

    def invoke(self, question: str) -> str:
        """Run the agent on a natural-language question and return the final answer.

        Opens one MCP server subprocess for the entire question so that
        multi-step questions (assess then record_decision) share a single
        SQLite connection and the assessment is visible to later tool calls.
        """
        self._ensure_built()
        assert self._agent is not None

        async def _run_with_client() -> Any:
            async with Client(_transport()) as client:
                loop = asyncio.get_running_loop()
                _mcp_client.set(client)
                _mcp_loop.set(loop)
                # Snapshot the context *after* setting the vars so the worker
                # thread inherits them (run_in_executor does not copy context).
                ctx = contextvars.copy_context()
                try:
                    # agent.invoke() is sync; run it in a worker thread so it
                    # can call asyncio.run_coroutine_threadsafe() back onto
                    # this event loop without deadlocking.
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        return await loop.run_in_executor(
                            pool,
                            lambda: ctx.run(  # propagate _mcp_client/_mcp_loop
                                self._agent.invoke,  # type: ignore[union-attr]
                                {"messages": [("user", question)]},
                            ),
                        )
                finally:
                    _mcp_client.set(None)
                    _mcp_loop.set(None)

        result = asyncio.run(_run_with_client())
        messages = result.get("messages", [])
        for msg in reversed(messages):
            content = getattr(msg, "content", None)
            if content and isinstance(content, str) and content.strip():
                return content.strip()
            if content and isinstance(content, list):
                text = " ".join(
                    b.get("text", "") if isinstance(b, dict) else str(b)
                    for b in content
                )
                if text.strip():
                    return text.strip()
        return str(result)
