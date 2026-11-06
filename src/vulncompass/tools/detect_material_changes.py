"""MCP registration for evidence snapshot change detection."""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP

from vulncompass.models import ChangeDetectionRequest
from vulncompass.service import detect_material_changes_service


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="detect_material_changes",
        annotations={
            "title": "Detect material public evidence changes",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def detect_material_changes(
        request: Annotated[
            ChangeDetectionRequest,
            "Stored finding or explicit before-and-after evidence snapshots.",
        ],
    ) -> dict[str, Any]:
        """Compare public evidence and identify findings requiring rereview."""
        return await detect_material_changes_service(request)

