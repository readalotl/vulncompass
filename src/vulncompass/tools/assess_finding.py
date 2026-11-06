"""MCP registration for a single evidence-backed finding assessment."""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP

from vulncompass.models import EvidenceMode, FindingInput
from vulncompass.service import assess_finding_service


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="assess_finding",
        annotations={
            "title": "Assess one vulnerability finding",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    )
    async def assess_finding(
        finding: Annotated[
            FindingInput,
            "Vendor finding plus locally supplied applicability and mission context.",
        ],
        mode: Annotated[
            EvidenceMode,
            "fixture for deterministic demo data, cached for local snapshots, "
            "or live for public sources.",
        ] = EvidenceMode.FIXTURE,
    ) -> dict[str, Any]:
        """Create a cited, deterministic assessment with PENDING_REVIEW status.

        Only the CVE identifier is used for public lookups. Asset identifiers,
        mission context, vendor details, and analyst data remain local.
        """
        assessment = await assess_finding_service(finding, mode)
        return assessment.model_dump(mode="json")
