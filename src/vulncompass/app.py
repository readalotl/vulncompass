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


def _make_auth_middleware(api_key: str):
    """Return a Starlette middleware that enforces Bearer token auth.

    Only active when ``MCP_API_KEY`` is set. Every incoming request must carry:
        Authorization: Bearer <api_key>

    Requests without a valid token receive a 401 JSON response.
    Health-check and non-MCP paths are also protected — the MCP server should
    sit behind a reverse proxy in production; this is a defence-in-depth layer.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    expected = f"Bearer {api_key}"

    class _BearerAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if request.headers.get("Authorization") != expected:
                return JSONResponse(
                    {"error": "Unauthorized", "detail": "Valid Bearer token required."},
                    status_code=401,
                )
            return await call_next(request)

    return _BearerAuthMiddleware


def main() -> None:
    platform_port = os.getenv("DATABRICKS_APP_PORT") or os.getenv("PORT")
    if platform_port:
        mcp.run(transport="http", host="0.0.0.0", port=int(platform_port))
    elif settings.mcp_transport == "streamable-http":
        kwargs: dict = {
            "transport": "streamable-http",
            "host": settings.mcp_host,
            "port": settings.mcp_port,
        }
        if settings.mcp_api_key:
            kwargs["middleware"] = [(_make_auth_middleware(settings.mcp_api_key), {})]
        mcp.run(**kwargs)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
