from __future__ import annotations

from fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt(name="review_vulnerability_backlog")
    def review_vulnerability_backlog(mode: str = "fixture") -> str:
        """Guide a human-reviewed vulnerability backlog workflow."""
        return (
            "Use prioritize_findings in "
            f"{mode} mode to create a bounded analyst-review queue. Then call "
            "assess_finding for the highest-ranked item. Clearly separate vendor "
            "assertions, public evidence, local context, policy results, and unknowns. "
            "Do not treat the recommendation as a final decision. Ask the analyst "
            "whether to approve, modify, reject, defer, or request investigation, "
            "and call record_analyst_decision only after the analyst chooses."
        )
