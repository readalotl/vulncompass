"""Smoke tests for the example MCP server.

These verify the server imports and every submodule registers without error.
Add functional tests for your own tools as you build them.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from vulncompass.app import mcp
from vulncompass.config import settings


def test_server_is_importable():
    assert mcp is not None


def test_server_has_name():
    assert mcp.name == "VulnCompass MCP"


def test_default_transport_is_stdio():
    """Guard against accidentally shipping with a non-stdio default."""
    assert settings.mcp_transport == "stdio"


def test_tools_register_without_error():
    from vulncompass.tools import register_tools

    register_tools(FastMCP("test"))  # must not raise


def test_prompts_register_without_error():
    from vulncompass.prompts import register_prompts

    register_prompts(FastMCP("test"))  # must not raise


def test_resources_register_without_error():
    from vulncompass.resources import register_resources

    register_resources(FastMCP("test"))  # must not raise


def test_routes_register_without_error():
    from vulncompass.routes import register_routes

    register_routes(FastMCP("test"))  # must not raise


@pytest.mark.asyncio
async def test_vulncompass_tools_are_discoverable():
    tools = await mcp.list_tools()
    tool_names = {t.name for t in tools}
    assert tool_names == {
        "assess_finding",
        "prioritize_findings",
        "detect_material_changes",
        "record_analyst_decision",
    }
