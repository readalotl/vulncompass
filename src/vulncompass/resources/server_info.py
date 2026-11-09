from __future__ import annotations

import json

from fastmcp import FastMCP

from vulncompass.policy import POLICY_VERSION


def register(mcp: FastMCP) -> None:
    @mcp.resource("vulncompass://info/server")
    def server_info() -> str:
        """Server scope, trust boundary, and policy version."""
        return json.dumps(
            {
                "name": "VulnCompass MCP",
                "purpose": "Vendor-neutral vulnerability decision support",
                "policy_version": POLICY_VERSION,
                "human_review_required": True,
                "public_lookup_fields": ["cve_id"],
                "local_only_fields": [
                    "asset_id",
                    "vendor finding data",
                    "applicability",
                    "internet exposure",
                    "mission criticality",
                    "compensating controls",
                    "analyst decisions",
                ],
                "not_supported": [
                    "vulnerability scanning",
                    "Nuclei template execution",
                    "Shodan asset lookup",
                    "risk acceptance",
                    "finding closure",
                    "patch deployment",
                ],
            },
            indent=2,
        )
