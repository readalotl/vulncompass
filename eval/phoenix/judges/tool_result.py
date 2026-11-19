"""Deterministic tool-result judge.

Fetches the raw JSON the VulnCompass MCP tool returned from a Phoenix span,
then asserts structured fields — no LLM involved.

Supported check keys (all optional; only supplied keys are asserted):

  assess_finding / any tool returning an assessment:
    recommendation  str   e.g. "proposed_closure"
    confidence      str   e.g. "high"
    policy_rules    list  e.g. ["A-4"]
    kev_listed      bool  checks evidence.kev.listed
    source_conflicts_contains  str  substring that must appear in at least
                                    one source_conflicts entry
    review_status   str   e.g. "PENDING_REVIEW"

  prioritize_findings:
    rank1_finding_id  str   finding_id of the first ranked finding
    rank1_recommendation  str
    rank1_confidence      str

  detect_material_changes:
    material_change_detected   bool
    requires_analyst_rereview  bool

  record_analyst_decision:
    review_status  str  "DECIDED"
    action         str  e.g. "defer"
    modified_recommendation  str  (optional, only when action=modify)
"""

from __future__ import annotations

import json
import re
from typing import Any

from eval.phoenix.judges.scope import fetch_spans_for_trace


# ── Span output extraction ────────────────────────────────────────────────────

def _extract_tool_output(
    spans: list[dict],
    tool_name: str,
) -> dict | None:
    """Return the parsed JSON output of the first matching tool span, or None."""
    for span in spans:
        name = span.get("name", "")
        attrs = span.get("attributes", {})
        actual_name = (
            attrs.get("tool.name")
            or attrs.get("llm.function_call.name")
            or name
        )
        if actual_name != tool_name:
            continue
        raw = attrs.get("output.value") or attrs.get("tool.output") or ""
        if not raw:
            continue
        # The MCP layer wraps the dict in a list of TextContent objects whose
        # JSON looks like [{"type": "text", "text": "{ ... }"}].
        # Try that first, then fall back to parsing raw directly.
        try:
            outer = json.loads(raw)
            if isinstance(outer, list) and outer and isinstance(outer[0], dict):
                inner_text = outer[0].get("text", "")
                if inner_text:
                    return json.loads(inner_text)
            if isinstance(outer, dict):
                return outer
        except (json.JSONDecodeError, TypeError):
            pass
    return None


# ── Field assertions ──────────────────────────────────────────────────────────

def _check(
    tool_output: dict,
    checks: dict[str, Any],
    tool_name: str,
) -> list[dict]:
    """Return one result dict per check key."""
    results = []

    def _pass(key: str, got: Any, want: Any) -> dict:
        return {"check": key, "passed": True, "want": want, "got": got}

    def _fail(key: str, got: Any, want: Any, reason: str = "") -> dict:
        return {"check": key, "passed": False, "want": want, "got": got, "reason": reason}

    # ── assess_finding / general assessment fields ────────────────────────────
    if "recommendation" in checks:
        want = checks["recommendation"].lower()
        got = str(tool_output.get("vulncompass_recommendation", "")).lower()
        results.append(_pass("recommendation", got, want) if got == want
                       else _fail("recommendation", got, want))

    if "confidence" in checks:
        want = checks["confidence"].lower()
        got = str(tool_output.get("confidence", "")).lower()
        results.append(_pass("confidence", got, want) if got == want
                       else _fail("confidence", got, want))

    if "policy_rules" in checks:
        want = sorted(checks["policy_rules"])
        got = sorted(tool_output.get("policy_rules", []))
        results.append(_pass("policy_rules", got, want) if got == want
                       else _fail("policy_rules", got, want))

    if "kev_listed" in checks:
        want = bool(checks["kev_listed"])
        evidence = tool_output.get("evidence", {}) or {}
        kev = evidence.get("kev") or {}
        got = kev.get("listed")
        results.append(_pass("kev_listed", got, want) if got is want or got == want
                       else _fail("kev_listed", got, want))

    if "source_conflicts_contains" in checks:
        want_sub = checks["source_conflicts_contains"].lower()
        conflicts = tool_output.get("source_conflicts", []) or []
        matched = any(want_sub in str(c).lower() for c in conflicts)
        got = conflicts
        results.append(_pass("source_conflicts_contains", got, want_sub) if matched
                       else _fail("source_conflicts_contains", got, want_sub,
                                  f"No conflict entry contains {want_sub!r}"))

    if "review_status" in checks:
        want = checks["review_status"].upper()
        # assess_finding returns review_status at top level;
        # record_analyst_decision also returns it at top level.
        got = str(tool_output.get("review_status", "")).upper()
        results.append(_pass("review_status", got, want) if got == want
                       else _fail("review_status", got, want))

    if "action" in checks:
        want = checks["action"].lower()
        got = str(tool_output.get("action", "")).lower()
        results.append(_pass("action", got, want) if got == want
                       else _fail("action", got, want))

    if "modified_recommendation" in checks:
        want = checks["modified_recommendation"].lower()
        got = str(tool_output.get("modified_recommendation", "")).lower()
        results.append(_pass("modified_recommendation", got, want) if got == want
                       else _fail("modified_recommendation", got, want))

    # ── prioritize_findings ───────────────────────────────────────────────────
    if any(k.startswith("rank1_") for k in checks):
        ranked = tool_output.get("ranked_findings", []) or []
        top = ranked[0] if ranked else {}

        if "rank1_finding_id" in checks:
            want = checks["rank1_finding_id"]
            got = top.get("finding_id")
            results.append(_pass("rank1_finding_id", got, want) if got == want
                           else _fail("rank1_finding_id", got, want))

        if "rank1_recommendation" in checks:
            want = checks["rank1_recommendation"].lower()
            got = str(top.get("vulncompass_recommendation", "")).lower()
            results.append(_pass("rank1_recommendation", got, want) if got == want
                           else _fail("rank1_recommendation", got, want))

        if "rank1_confidence" in checks:
            want = checks["rank1_confidence"].lower()
            got = str(top.get("confidence", "")).lower()
            results.append(_pass("rank1_confidence", got, want) if got == want
                           else _fail("rank1_confidence", got, want))

    # ── detect_material_changes ───────────────────────────────────────────────
    if "material_change_detected" in checks:
        want = bool(checks["material_change_detected"])
        got = bool(tool_output.get("material_change_detected"))
        results.append(_pass("material_change_detected", got, want) if got == want
                       else _fail("material_change_detected", got, want))

    if "requires_analyst_rereview" in checks:
        want = bool(checks["requires_analyst_rereview"])
        got = bool(tool_output.get("requires_analyst_rereview"))
        results.append(_pass("requires_analyst_rereview", got, want) if got == want
                       else _fail("requires_analyst_rereview", got, want))

    return results


# ── Public interface ──────────────────────────────────────────────────────────

def run_tool_checks(
    expected_tool_checks: list[dict],
    trace_ids: list[str | None],
    *,
    phoenix_host: str = "http://localhost:6006",
    project_name: str = "vulncompass-eval",
) -> list[dict]:
    """Run deterministic field checks against Phoenix span outputs.

    Args:
        expected_tool_checks: One dict per dataset row.  Each dict must have
            a ``tool`` key naming the VulnCompass tool to inspect, plus any
            combination of check keys documented in the module docstring.
            Pass an empty dict ``{}`` for rows where no tool check is needed.
        trace_ids:  Hex trace IDs aligned with expected_tool_checks.
        phoenix_host, project_name: Passed to fetch_spans_for_trace.

    Returns:
        One result dict per row with keys:
            score        1 = all checks passed, 0 = any failed, -1 = no output
            checks       list of per-check result dicts
            explanation  human-readable summary
    """
    results = []
    for checks, trace_id in zip(expected_tool_checks, trace_ids):
        if not checks:
            results.append({
                "score": 1,
                "checks": [],
                "explanation": "No tool checks defined for this row.",
            })
            continue

        tool_name = checks.get("tool", "")
        check_fields = {k: v for k, v in checks.items() if k != "tool"}

        if not tool_name:
            results.append({
                "score": 0,
                "checks": [],
                "explanation": "expected_tool_checks entry has no 'tool' key.",
            })
            continue

        if not trace_id:
            results.append({
                "score": 0,
                "checks": [],
                "explanation": "No trace ID available; cannot fetch span output.",
            })
            continue

        spans = fetch_spans_for_trace(
            trace_id,
            phoenix_host=phoenix_host,
            project_name=project_name,
        )
        tool_output = _extract_tool_output(spans, tool_name)

        if tool_output is None:
            results.append({
                "score": -1,
                "checks": [],
                "explanation": (
                    f"No output found for tool '{tool_name}' in trace {trace_id}. "
                    "The tool may not have been called, or the span has not flushed yet."
                ),
            })
            continue

        check_results = _check(tool_output, check_fields, tool_name)
        all_passed = all(c["passed"] for c in check_results)
        failed = [c for c in check_results if not c["passed"]]

        results.append({
            "score": 1 if all_passed else 0,
            "checks": check_results,
            "explanation": (
                "All tool checks passed."
                if all_passed
                else f"{len(failed)} check(s) failed: "
                     + "; ".join(
                         f"{c['check']}: want {c['want']!r}, got {c['got']!r}"
                         for c in failed
                     )
            ),
        })

    return results
