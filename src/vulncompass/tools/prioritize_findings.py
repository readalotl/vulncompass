"""MCP registration for bounded backlog prioritization."""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP

from vulncompass.models import PrioritizeRequest
from vulncompass.service import prioritize_findings_service


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="prioritize_findings",
        annotations={
            "title": "Create an analyst review queue",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    )
    async def prioritize_findings(
        request: Annotated[
            PrioritizeRequest,
            "One to 200 structured findings or local CSV text, evidence mode, "
            "and maximum queue length.",
        ],
    ) -> dict[str, Any]:
        """Rank findings for analyst review without replacing the vendor queue."""
        return await prioritize_findings_service(request)
