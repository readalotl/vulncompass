# VulnCompass MCP

VulnCompass is a local-first Model Context Protocol server that helps federal
vulnerability analysts reconcile vendor findings with authoritative public
evidence and transparent policy rules. It preserves the vendor recommendation,
keeps priority separate from confidence, and marks every recommendation
`PENDING_REVIEW` until a human analyst records a decision.

This project is based on the
[GSA-TTS MCP Hackathon Template](https://github.com/GSA-TTS/mcp-hackathon-template)
and retains its FastMCP structure, test workflow, container build, cloud.gov
manifest, and deployment kits.

## What it does

- Accepts a generic vendor finding with locally supplied applicability,
  exposure, mission criticality, and compensating-control status.
- Retrieves CVE Program, NVD, CISA KEV, CISA Vulnrichment, and optional
  ProjectDiscovery Nuclei template metadata using only the CVE ID.
- Applies inspectable deterministic policy rules instead of an opaque score.
- Explains agreement or disagreement with the vendor without claiming that the
  vendor is wrong.
- Produces a bounded analyst-review queue.
- Detects material changes between public-evidence snapshots.
- Stores the analyst's final action and rationale locally.

VulnCompass does not scan assets, execute Nuclei templates, query Shodan with
organizational addresses, prove product applicability, accept risk, close
findings, deploy patches, or write back to a commercial platform.

## Trust boundary

Only the CVE identifier and public API parameters may leave the local
environment. Asset identifiers, vendor finding details, exposure, mission
criticality, compensating controls, and analyst decisions are written only to
the local SQLite database under `DATA_DIR`.

Live mode uses five fixed HTTPS origins:

- `cveawg.mitre.org` for the CVE Program CVE Services record
- `services.nvd.nist.gov` for NVD CVE API 2.0
- `www.cisa.gov` for the Known Exploited Vulnerabilities JSON feed
- `raw.githubusercontent.com/cisagov/vulnrichment` for CISA ADP records
- `raw.githubusercontent.com/projectdiscovery/nuclei-templates` for the
  community CVE template metadata index

Nuclei metadata is supporting evidence only. A template indicates that a
community detection or proof-of-concept check is available; it does not prove
weaponization, exploitation in the wild, or local applicability. VulnCompass
does not download or execute template payloads. Direct Shodan integration is
intentionally excluded because the project trust boundary requires hostnames,
IP addresses, and exposure data to remain local.

Redirects and environment proxy inheritance are disabled, responses are size
bounded, and error messages do not include upstream response bodies. Network
egress controls should enforce the same allowlist in any deployed environment.
Remote authentication and multi-user authorization are outside this hackathon
MVP; do not expose HTTP transport to an untrusted network.

## MCP tools

| Tool | Purpose | State change |
| --- | --- | --- |
| `assess_finding` | Build one evidence-backed recommendation | Saves assessment and evidence snapshot locally |
| `prioritize_findings` | Rank up to 200 findings into a bounded review queue | Saves each assessment locally |
| `detect_material_changes` | Compare stored or supplied evidence snapshots | None |
| `record_analyst_decision` | Record approve, modify, reject, defer, or investigate | Appends a local decision record |

The server also exposes the `review_vulnerability_backlog` prompt and the
`vulncompass://info/server` resource.

## Evidence modes

- `fixture` is the default and uses deterministic synthetic CVEs in
  `src/vulncompass/data/fixtures.json`.
- `cached` reads a prior public evidence snapshot from `DATA_DIR/cache` and
  performs no network request.
- `live` retrieves current public evidence and updates the local public cache.

## Run locally

Prerequisite: [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env
uv sync --group dev
uv run python main.py
```

The default transport is stdio. A client configuration can invoke the installed
script directly:

```json
{
  "mcpServers": {
    "vulncompass": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/VulnCompass", "run", "vulncompass-mcp"]
    }
  }
}
```

For a local HTTP demonstration, set `MCP_TRANSPORT=streamable-http`; the default
bind address is loopback-only (`127.0.0.1`).

## Fixture demonstration

Use `CVE-2099-0001` for a synthetic KEV-listed case with Nuclei metadata,
`CVE-2099-0002` for a synthetic non-KEV case without a template, and
`CVE-2099-0003` for a synthetic rejected CVE with conflicting community
metadata. A
ten-finding backlog is provided in `examples/demo_findings.csv`, and
`examples/material_change_request.json` demonstrates a KEV, CVSS, affected
version, and exploitation-status change.

Example finding:

```json
{
  "finding_id": "F-001",
  "source_vendor": "synthetic-vendor",
  "source_finding_id": "V-9182",
  "cve_id": "CVE-2099-0001",
  "asset_id": "ASSET-001",
  "vendor_severity": "High",
  "vendor_risk_score": 742,
  "vendor_priority": "High",
  "vendor_evidence_timestamp": "2026-10-30T12:00:00Z",
  "applicability": "confirmed_affected",
  "internet_exposure": "public",
  "mission_criticality": "high",
  "compensating_controls": "absent"
}
```

Suggested sequence:

1. Call `prioritize_findings` with 10-20 synthetic findings.
2. Call `assess_finding` for the highest-ranked item.
3. Inspect vendor evidence, public evidence, local context, rules, missing data,
   and confidence independently.
4. After a human choice, call `record_analyst_decision`.
5. Supply an earlier and later snapshot to `detect_material_changes` to
   demonstrate a KEV addition or CVSS/status change.

## Policy summary

The MVP policy version is `2026.11.2`.

- Confirmed or likely affected plus KEV: immediate review.
- KEV plus unknown applicability: investigate applicability immediately.
- Confirmed affected, public, and mission-critical: accelerated remediation.
- Confirmed not affected: proposed closure, subject to human review.
- Unknown applicability or missing local context: investigate; missing data
  never automatically reduces priority.
- Otherwise: routine remediation.
- A Nuclei template is shown as caveated supporting evidence and never changes
  priority by itself.
- A rejected CVE Program record that conflicts with NVD, KEV, or Nuclei is
  surfaced as a source conflict and lowers confidence.

Confidence is high only when key local context is known, public evidence is
available, and no material conflict exists. It is not a probability.

## Verify

```bash
uv run pytest -v
uv run ruff check .
```

Tests cover policy outcomes, queue bounds and duplicate handling, material
change detection, local analyst decisions, fixed outbound origins, redirect and
proxy policy, sanitized upstream errors, and the rule that organizational
fields never enter public requests.

## Project structure

```text
src/vulncompass/
├── app.py            FastMCP assembly and transport selection
├── evidence.py       CVE Program, NVD, KEV, Vulnrichment, Nuclei adapters
├── models.py         Pydantic tool contracts and enums
├── policy.py         deterministic recommendation rules
├── service.py        workflow orchestration
├── storage.py        local SQLite repository
├── tools/            one module per MCP tool
├── prompts/          analyst workflow prompt
└── resources/        server trust-boundary resource
```

## Deployment

The inherited `deploy/` kits and `manifest.yaml` support cloud.gov, IBM, and
Databricks packaging. They are demonstration scaffolds, not production security
profiles. Before remote deployment, add platform authentication, per-tool
authorization, encrypted storage, ingress restrictions, and enforced egress
allowlisting.

## License

MIT. See `LICENSE` and `SECURITY.md`.
