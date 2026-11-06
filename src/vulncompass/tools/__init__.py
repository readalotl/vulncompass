"""Register all VulnCompass workflow tools."""

from vulncompass.tools import (
    assess_finding,
    detect_material_changes,
    prioritize_findings,
    record_analyst_decision,
)


def register_tools(mcp) -> None:
    assess_finding.register(mcp)
    prioritize_findings.register(mcp)
    detect_material_changes.register(mcp)
    record_analyst_decision.register(mcp)

