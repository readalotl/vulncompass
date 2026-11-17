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

        When presenting the result, always include:
        - vulncompass_recommendation, confidence, policy_rules, and review_status
          verbatim from the tool response.
        - The agreement field and comparison_explanation together: state whether
          vendor priority and VulnCompass recommendation agree, and quote the
          comparison_explanation. If agreement is false, make clear this does not
          mean the vendor is wrong.
        - Any entry in the rationale list that mentions Nuclei must be quoted in
          full; it is not proof of weaponization, active exploitation, or local
          applicability.
        - missing_information and source_conflicts when non-empty.
        Do not invent, omit, or paraphrase these fields.
        """
        assessment = await assess_finding_service(finding, mode)
        return assessment.model_dump(mode="json")
