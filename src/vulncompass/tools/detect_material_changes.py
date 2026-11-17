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
        """Compare public evidence and identify findings requiring rereview.

        The request must include cve_id at the top level (not only inside the
        snapshots). When supplying explicit before-and-after snapshots, each
        snapshot must also carry the same cve_id and a retrieved_at timestamp.

        KEV status inside a snapshot uses the key "listed" (boolean), not
        "is_in_kev". Example snapshot kev object: {"listed": true}.

        When presenting the result, always include:
        - material_change_detected and requires_analyst_rereview verbatim.
        - Each entry in changes as: <field>: <old_value> → <new_value> (<reason>).
        - If material_change_detected is false, state "No material changes
          detected since last assessment."
        Do not paraphrase or omit these fields.
        """
        return await detect_material_changes_service(request)
