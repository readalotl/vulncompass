from __future__ import annotations

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from vulncompass import __version__


def register_routes(mcp: FastMCP) -> None:
    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy", "service": "vulncompass-mcp"})

    @mcp.custom_route("/version", methods=["GET"])
    async def version(request: Request) -> JSONResponse:
        return JSONResponse({"version": __version__})

