"""Thin FastMCP entry point for VulnCompass."""

from __future__ import annotations

import os

from fastmcp import FastMCP

from vulncompass.config import settings
from vulncompass.prompts import register_prompts
from vulncompass.resources import register_resources
from vulncompass.routes import register_routes
from vulncompass.tools import register_tools

mcp = FastMCP(
    name="VulnCompass MCP",
    instructions=(
        "Vendor-neutral vulnerability decision support for federal analysts. "
        "Preserve vendor conclusions, distinguish public evidence from local context, "
        "apply deterministic rules, state uncertainty, and keep every recommendation "
        "pending until a human analyst records a decision."
    ),
)

register_tools(mcp)
register_prompts(mcp)
register_resources(mcp)
register_routes(mcp)


def main() -> None:
    platform_port = os.getenv("DATABRICKS_APP_PORT") or os.getenv("PORT")
    if platform_port:
        mcp.run(transport="http", host="0.0.0.0", port=int(platform_port))
    elif settings.mcp_transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=settings.mcp_host,
            port=settings.mcp_port,
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

