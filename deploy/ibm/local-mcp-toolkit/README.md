# watsonx Orchestrate — Local MCP Toolkit (stdio)

Register your MCP server as a **local MCP toolkit**: you ship the server *code*
to watsonx Orchestrate, which installs it (via a `requirements.txt`) and runs it
**over stdio inside the Orchestrate runtime**. There is **no HTTP endpoint, no
container, no Code Engine, and no image registry** — the lowest-overhead path
for a novice to get a Python MCP server into Orchestrate.

> **Why this is the lowest-overhead route.** Ranked by setup burden:
>
> | Option | You must… | Overhead |
> |---|---|---|
> | **Local MCP toolkit (this kit)** | drop a `server.py` + `requirements.txt`, run one command | **Lowest** — reuses your FastMCP server unchanged; no HTTP, no deploy |
> | **Remote MCP toolkit** (`../code-engine-git-build/`, `../prebuilt-image/`) | build/deploy an HTTP server to Code Engine, manage a public URL | Medium — cloud deploy + (maybe) registry authority |
>
> Trade-off: it runs *inside* Orchestrate with a ~100–300 ms process-startup cost
> per call (fine for moderate use), and it only works from a machine that has the
> ADK + your repo.

## How it reuses this template

`server.py` in this folder is a tiny stdio entrypoint that imports the existing
FastMCP app (`vulncompass.app:mcp`) and runs it over stdio. The register
script stages a **flattened** copy of the package so **you do not duplicate or
rewrite any tool code** — edits in `src/vulncompass/` are picked up on the
next import.

```
deploy/ibm/local-mcp-toolkit/
├── server.py              # stdio entrypoint: `from vulncompass.app import mcp; mcp.run(transport="stdio")`
├── requirements.txt       # pinned runtime deps staged next to the package
├── toolkit.yaml           # import config template (kind: mcp, command: python server.py, tools: *)
├── register-toolkit.sh    # stage flattened package_root + activate ADK env + import (idempotent)
├── vulncompass_agent.yaml # native agent definition — imports the toolkit tools, no UI required
├── .env.example           # instance URL + env/toolkit names (no secrets)
└── README.md              # this runbook
```

> **How the register script assembles the upload:** Orchestrate uploads
> `package_root`, installs a `requirements.txt` found there, then runs `command`
> over stdio. The script builds a small **staging** dir (`_stage/`, git-ignored)
> containing a **flattened** copy of the package — `vulncompass/` and
> `server.py` at the top level (no `src/` prefix) plus the pinned
> `requirements.txt` — and points `package_root` at it. This avoids a 413
> (uploading the whole repo), a `ModuleNotFoundError` (src-layout not importable
> at runtime), and a missing-deps error (the ADK reads `requirements.txt`).

---

## Part 1 — Prerequisites

```bash
pip install --upgrade ibm-watsonx-orchestrate   # Python 3.11-3.14
orchestrate --version
```

Your Orchestrate instance URL + API key are on the wxO service page in IBM Cloud
(Resource List → your watsonx Orchestrate instance).

> **Security:** treat the API key as a secret. Pass it via `WXO_API_KEY`; never
> commit it.

---

## Part 2 — Register the toolkit

### 2.1 Configure the env file

```bash
cp deploy/ibm/local-mcp-toolkit/.env.example deploy/ibm/local-mcp-toolkit/.env
# edit: WXO_INSTANCE_URL, WXO_ENV_NAME / TOOLKIT_NAME (defaults are fine)
set -a; source deploy/ibm/local-mcp-toolkit/.env; set +a
```

### 2.2 Provide your API key and run the register script

```bash
export WXO_API_KEY="<your Orchestrate API key>"   # else prompted (hidden)
bash deploy/ibm/local-mcp-toolkit/register-toolkit.sh
```

The script activates the ADK env, stages a minimal flattened `package_root`,
imports the toolkit, lists toolkits to confirm, and cleans up. It is idempotent
(re-runs pick up code/dependency changes).

> **If you renamed the package** from `vulncompass`, run with
> `PACKAGE_NAME=<your_pkg>` exported (and update `server.py`'s import).

### 2.2a Corporate TLS interception (Zscaler / GSA network) — may be required

On a GSA-managed network the ADK's IAM login may fail with
`SSLCertVerificationError: unable to get local issuer certificate`. This is a
TLS-inspection proxy re-signing HTTPS with a private CA that Python's `certifi`
bundle doesn't trust. Fix by giving Python a CA bundle that includes the proxy
root exported from the keychain:

```bash
# 1. Confirm interception (issuer names your proxy, e.g. Zscaler):
openssl s_client -connect iam.cloud.ibm.com:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer

# 2. Export the proxy root(s) from the macOS System keychain:
security find-certificate -a -c "Zscaler" -p /Library/Keychains/System.keychain \
  > /tmp/zscaler-roots.pem 2>/dev/null
security find-certificate -a -c "Zscaler" -p /System/Library/Keychains/SystemRootCertificates.keychain \
  >> /tmp/zscaler-roots.pem 2>/dev/null

# 3. Merge with certifi:
CERTIFI="$(python -c 'import certifi; print(certifi.where())')"
cat "$CERTIFI" /tmp/zscaler-roots.pem > /tmp/wxo-ca-bundle.pem

# 4. Point the ADK at the merged bundle IN THIS SHELL, then run the register script:
export SSL_CERT_FILE=/tmp/wxo-ca-bundle.pem
export REQUESTS_CA_BUNDLE=/tmp/wxo-ca-bundle.pem
```

### 2.3 (Optional) Verify the entrypoint locally first

```bash
# From the repo root, with the repo installed (uv sync or pip install -e .):
python deploy/ibm/local-mcp-toolkit/server.py
# It blocks waiting for MCP stdio input; Ctrl-C to exit. No error = good.
```

---

## Part 3 — Deploy the agent

`vulncompass_agent.yaml` is a **native agent definition** that wires the four
toolkit tools to a Granite 3 8B instruction-following LLM with a pre-written
system prompt. Import it with the ADK — no UI required.

### 3.1 Import the agent

```bash
orchestrate agents import -f deploy/ibm/local-mcp-toolkit/vulncompass_agent.yaml
```

Verify it registered:

```bash
orchestrate agents list
```

### 3.2 Chat-test in the CLI

```bash
orchestrate chat ask --agent-name vulncompass_agent
```

To send a single question without entering interactive mode:

```bash
orchestrate chat ask --agent-name vulncompass_agent \
  "Assess finding F-001 for CVE-2099-0001. Asset ASSET-001 reported by \
synthetic-vendor (finding V-1001). Confirmed affected, publicly exposed, \
mission-critical, no compensating controls. Vendor scored it High."
```

Add `--include-reasoning` to see the tool-call trace:

```bash
orchestrate chat ask --agent-name vulncompass_agent --include-reasoning
```

Ask it a question that requires a tool call, for example:

```
Assess finding F-001 for CVE-2099-0001. Asset ASSET-001 reported by
synthetic-vendor (finding V-1001). Confirmed affected, publicly exposed,
mission-critical, no compensating controls. Vendor scored it High.
```

The agent should call `assess_finding`, not answer from memory.

### 3.3 (Optional) Edit the agent before importing

The YAML lives at [`vulncompass_agent.yaml`](vulncompass_agent.yaml). Editable
fields:

| Field | Default | Why you'd change it |
|---|---|---|
| `llm` | `watsonx/ibm/granite-3-8b-instruct` | Swap to another watsonx model |
| `instructions` | VulnCompass system prompt | Tune tool-call behaviour |
| `name` | `vulncompass_agent` | Rename the agent |

Re-import after edits (`orchestrate agents import` is idempotent — it replaces
an existing agent with the same name).

---

## Connections (only if your server needs secrets)

This template's server needs **no credentials**, so `toolkit.yaml` declares no
`connections`. If you adapt it for a server that needs secrets:

```bash
orchestrate connections add -a my_connection
for env in draft live; do
  orchestrate connections configure -a my_connection --env $env --type team --kind key_value
  orchestrate connections set-credentials -a my_connection --env $env -e "SECURE_VAR=value"
done
# then add `connections: [my_connection]` to toolkit.yaml
```

---

## Teardown

```bash
orchestrate agents remove --name vulncompass_agent
orchestrate toolkits remove --name vulncompass
```

---

## Known gaps / notes

- **Runs inside Orchestrate:** no public endpoint, so you can't curl it. Verify
  by chat-testing in the UI, or run `server.py` locally (2.3).
- **Startup overhead:** process-per-invocation adds ~100–300 ms/call. Fine for a
  hackathon; for high-frequency tools the ADK docs recommend a Python toolkit.
- **Import machine needs Python + the repo:** run the register script from a
  machine that has the ADK and a checkout of your repo.
