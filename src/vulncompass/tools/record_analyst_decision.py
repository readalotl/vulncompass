"""MCP registration for the mandatory human review record."""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP

from vulncompass.models import AnalystDecisionInput
from vulncompass.service import record_analyst_decision_service


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="record_analyst_decision",
        annotations={
            "title": "Record a local analyst decision",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    )
    async def record_analyst_decision(
        decision: Annotated[
            AnalystDecisionInput,
            "Human action and rationale for a previously assessed finding.",
        ],
    ) -> dict[str, Any]:
        """Store approval, modification, rejection, deferral, or investigation locally.

        This tool never changes a scanner, closes a finding, accepts risk, or
        deploys remediation.
        """
        return record_analyst_decision_service(decision)
