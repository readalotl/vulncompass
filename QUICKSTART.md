# VulnCompass quick start

```bash
cp .env.example .env
uv sync --group dev
uv run pytest -v
uv run python main.py
```

The server starts over stdio and defaults to deterministic fixture evidence.
Configure your MCP client to run `uv --directory /absolute/path/to/VulnCompass
run vulncompass-mcp`.

Start with `CVE-2099-0001` and call `assess_finding` using the example finding in
`README.md`. The result must remain `PENDING_REVIEW`. Call
`record_analyst_decision` only after a human selects an action.

Set `mode` to `live` only when current public evidence is required. Live mode
sends the CVE ID to the fixed NVD, CISA KEV, and CISA Vulnrichment origins and
caches the public response under `.vulncompass/cache`.

