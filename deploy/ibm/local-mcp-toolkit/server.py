#!/usr/bin/env python
"""Local MCP toolkit entrypoint for watsonx Orchestrate (stdio transport).

watsonx Orchestrate runs a LOCAL MCP toolkit by starting this script inside its
own runtime and speaking MCP over stdio. This entrypoint reuses the EXISTING
FastMCP server defined in the `vulncompass` package and runs it over stdio —
no HTTP, no Code Engine, no container.

The register script stages this file NEXT TO the `vulncompass` package
(flattened out of the repo's src/ layout), so `vulncompass` is importable
from this script's own directory. We add that directory to sys.path defensively
in case Orchestrate runs the command from a different working directory.

Orchestrate invokes:  python server.py
"""

import os
import sys

# Ensure the directory containing this file (which also contains the
# `vulncompass` package after staging) is importable, regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

# Anchor DATA_DIR to a stable absolute path next to this script so that the
# SQLite database persists correctly across invocations even when watsonx
# Orchestrate spawns a fresh process per tool call from an unpredictable CWD.
# An explicit DATA_DIR env var always takes precedence (e.g. for testing).
if not os.environ.get("DATA_DIR"):
    os.environ["DATA_DIR"] = os.path.join(_HERE, ".vulncompass")

from vulncompass.app import mcp  # noqa: E402

if __name__ == "__main__":
    # stdio is the transport watsonx Orchestrate uses for local MCP toolkits.
    mcp.run(transport="stdio")
