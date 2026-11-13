# VulnCompass Evaluation

End-to-end behavioral evaluation of the VulnCompass MCP agent using
[Arize Phoenix](https://phoenix.arize.com) as the experiment platform.

---

## 1. Testing Methodology

### What is being tested

The evaluation harness tests the full end-to-end behavior of a LangGraph
ReAct agent connected to the VulnCompass MCP server. It does not test
individual Python functions — those are covered by the unit test suite in
`tests/`. Instead it asks: *can an LLM agent correctly use the MCP server
to answer vulnerability management questions?*

Each evaluation question requires the agent to:
1. Select the correct tool (`assess_finding`, `prioritize_findings`,
   `detect_material_changes`, or `record_analyst_decision`).
2. Construct valid arguments from natural-language input.
3. Relay the tool's structured output as a correct prose answer.

### Dataset

15 gold questions in
[`datasets/vulncompass/vulncompass.csv`](phoenix/datasets/vulncompass/vulncompass.csv)
(authoritative source:
[`datasets/vulncompass/evaluation.xml`](phoenix/datasets/vulncompass/evaluation.xml)).
All questions use synthetic CVE fixtures (CVE-2099-0001, CVE-2099-0002,
CVE-2099-0003) so the harness runs deterministically without live network
access.

| ID | Tool exercised | Key expected facts |
|----|---------------|-------------------|
| Q-01 | `assess_finding` | `immediate_review`, `CISA KEV`, `high confidence` |
| Q-02 | `assess_finding` | `proposed_closure`, `confirmed not affected`, `high confidence` |
| Q-03 | `assess_finding` | `investigate_applicability`, `fields are unknown` |
| Q-04 | `assess_finding` | `REJECTED`, `Nuclei` |
| Q-05 | `prioritize_findings` | `F-002`, `immediate_review`, `rank` |
| Q-06 | `prioritize_findings` | `proposed_closure`, `confirmed not affected` |
| Q-07 | `detect_material_changes` | `material_change_detected`, `requires_analyst_rereview` |
| Q-08 | `assess_finding` → `record_analyst_decision` | `DECIDED`, `approve`, `accelerated_remediation` |
| Q-09 | `assess_finding` → `record_analyst_decision` | `DECIDED`, `modify`, `routine_remediation` |
| Q-10 | `record_analyst_decision` (error path) | `Assess the finding before recording an analyst decision` |
| Q-11 | `assess_finding` | `proposed_closure`, `priority bands differ` |
| Q-12 | `assess_finding` | `accelerated_remediation`, `publicly exposed`, `mission critical` |
| Q-13 | `assess_finding` → `record_analyst_decision` | `DECIDED`, `defer` |
| Q-14 | `assess_finding` → `record_analyst_decision` | `DECIDED`, `request_investigation` |
| Q-15 | `detect_material_changes` | `no material changes`, `no re-review required` |

### Judges

| Judge | What it checks | Deterministic? |
|-------|---------------|----------------|
| **Scope** | Did the agent call a VulnCompass tool (vs. answering from memory)? Reads Phoenix spans — no LLM needed. | Yes |
| **Correctness** | Does the answer contain all expected facts? LLM-as-judge (`gpt-4o-mini`). | No — varies ±10% run-to-run |

**Expected facts are anchored to verbatim tool output strings** (e.g.
`"immediate_review"`, `"Assess the finding before recording an analyst
decision"`) rather than prose paraphrases. This minimises judge variance
caused by the LLM rewording tool results.

### Scope judge internals

1. `run_experiment.py` wraps each question in an OpenTelemetry root span.
2. The LangChain instrumentor traces every LLM call and tool invocation as
   child spans under that root.
3. After all questions finish, a 15-second flush wait lets the OTLP exporter
   deliver spans to Phoenix.
4. `scope.py::run_scope()` calls
   `phoenix.client.Client.spans.get_spans_dataframe()` filtered by
   `context.trace_id` and looks for any span whose `name` or
   `attributes.tool.name` matches a known VulnCompass tool.

Score = 1 if a tool call is found, 0 otherwise.

### Correctness judge internals

Uses Phoenix 21.x `ClassificationEvaluator` with
`choices={"correct": 1, "incorrect": 0}`. The judge LLM receives the
question, the expected facts list, and the agent's answer, and classifies
whether **all** expected facts are present.

---

## 2. Performance Metrics

### Final results (gpt-4o-mini agent + judge, fixture mode)

| Metric | Score |
|--------|-------|
| **Scope** (tool called) | **100%** (15 / 15) |
| **Correctness** (LLM judge) | **100%** (15 / 15) |

These results were achieved after three targeted fixes described in
[§ 4 Lessons Learned](#4-lessons-learned-and-recommendations). The 100%
correctness result is the best single-run outcome; due to LLM judge
non-determinism the expected stable range is **93–100%** across repeated
runs on the same code.

### Results by question

| ID | Scope | Correctness | Notes |
|----|-------|-------------|-------|
| Q-01 | PASS | PASS | KEV + confirmed affected → immediate_review |
| Q-02 | PASS | PASS | confirmed_not_affected → proposed_closure |
| Q-03 | PASS | PASS | applicability unknown → investigate_applicability |
| Q-04 | PASS | PASS | Rejected CVE + Nuclei conflict detected |
| Q-05 | PASS | PASS | F-002 ranks first (KEV, lower confidence sorts higher) |
| Q-06 | PASS | PASS | F-004 → proposed_closure despite highest vendor score |
| Q-07 | PASS | PASS | KEV addition + CVSS vector change → re-review required |
| Q-08 | PASS | PASS | Two-step: assess then approve |
| Q-09 | PASS | PASS | Two-step: assess then modify recommendation |
| Q-10 | PASS | PASS | Error path: decision without prior assessment |
| Q-11 | PASS | PASS | Priority band disagreement correctly flagged |
| Q-12 | PASS | PASS | L-1 rule: confirmed affected + public + high criticality |
| Q-13 | PASS | PASS | Two-step: assess then defer |
| Q-14 | PASS | PASS | Two-step: assess then request_investigation |
| Q-15 | PASS | PASS | Identical snapshots → no material changes |

### CI thresholds

| Check | Threshold | Trigger |
|-------|-----------|---------|
| Scope | ≥ 100% | Every push / PR (hard gate in `ci.yml`) |
| Correctness | ≥ 90% | Nightly + manual dispatch only (`eval.yml`) |

The scope check is a hard gate on every commit because it is deterministic.
The correctness check is not a hard gate on every commit because a single
LLM judge run can vary by ±10% on identical code (observed range: 87–100%
across the same commit on consecutive CI runs).

---

## 3. Security Considerations

### Authentication and transport

**This is an unauthenticated sandbox prototype. It is not approved or
suitable for production use.**

The server has three startup paths, each with different auth behavior:

| Startup path | Trigger | Auth enforced? |
|---|---|---|
| `stdio` | default, eval harness | N/A — local pipe, no network exposure |
| `streamable-http` | `MCP_TRANSPORT=streamable-http` | Only if `MCP_API_KEY` is set; silently unauthenticated if the key is absent |
| Platform HTTP | `DATABRICKS_APP_PORT` or `PORT` set | **Never** — auth middleware is not applied on this path |

The platform HTTP path (`DATABRICKS_APP_PORT` / `PORT`) binds to
`0.0.0.0` with no authentication regardless of whether `MCP_API_KEY` is
set. Any client that can reach the port can call every tool.

**Before any non-hackathon deployment:**

- Fix the platform HTTP path to apply auth middleware on the same
  conditions as the `streamable-http` path.
- Require `MCP_API_KEY` to be set when any HTTP transport is used; refuse
  to start if it is absent.
- Front the endpoint with a reverse proxy that enforces mTLS or token
  authentication as a defence-in-depth layer.
- Review your agency's ATO requirements before connecting to any network
  beyond localhost.
- Never commit secrets — keep API keys in environment variables or `.env`
  (git-ignored), never in source.

### Input trust boundary

**Treat all tool arguments, retrieved content, and agent-to-agent messages
as untrusted.** Specific rules:

- Do not include upstream response bodies, headers, full URLs, query
  strings, stack traces, credentials, or PII in MCP errors or logs.
- Use structured logs with explicitly allowlisted fields.
- Define retention and access controls before processing any PII.

### URL and network safety

The HTTP helper used for evidence fetching:

- Uses a fixed API origin and rejects absolute or path-escaping inputs.
- Disables redirects and environment proxies.
- Sanitizes upstream failures before surfacing them.

If a tool must fetch arbitrary URLs, require exact destination allowlists,
connection-time validation of every resolved IPv4/IPv6 address, validation
at every redirect hop, credential stripping across origins, and
network-level egress controls. A DNS lookup followed by a normal hostname
request is vulnerable to DNS rebinding.

### Data sources and scope

VulnCompass consumes only the ProjectDiscovery Nuclei CVE metadata index.
It does **not** execute templates or retrieve payload bodies. Template
presence is not treated as proof of weaponization or local applicability.

Direct Shodan lookups are outside the trust boundary — organizational
hostnames, IP addresses, and network-exposure data must remain local and
are never sent to public sources.

### Dependency vulnerabilities

As of the current release all known CVEs in direct and transitive
dependencies have been remediated by explicit minimum version constraints
in `pyproject.toml`:

| Package | Fixed version | CVEs resolved |
|---------|--------------|---------------|
| `fastmcp` | ≥ 4.1.2 | GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4 |
| `authlib` | ≥ 1.9.1 | CVE-2026-96760, CVE-2026-116672 + 6 PYSEC |
| `dnspython` | ≥ 2.9.0 | CVE-2026-114605 |
| `joserfc` | ≥ 1.7.6 | CVE-2026-119284 |
| `opentelemetry-api` | ≥ 1.45.2 | CVE-2026-126360 |

---

## 4. Lessons Learned and Recommendations

### L-1 — Scope and correctness require different gating strategies

The scope check (did the agent call a tool?) is fully deterministic and
safe as a hard CI gate. The LLM-as-judge correctness check is not: on
identical code and identical questions the same `gpt-4o-mini` judge
produced scores ranging from 87% to 100% across consecutive runs. Treating
a single non-deterministic run as a binary pass/fail gate blocked valid
commits and produced contradictory results (the separate `eval.yml`
workflow passed on the same commit that `ci.yml` failed).

**Recommendation:** Keep scope as the per-commit hard gate. Run correctness
on a schedule (nightly) and manually before releases. Use aggregate results
across multiple runs rather than a single run to decide whether a prompt or
policy change regressed correctness.

### L-2 — Expected facts must be anchored to verbatim tool output

Expected facts written as natural-language phrases (e.g. "Immediate
Review", "applicability is unknown") are sensitive to how the LLM judge
paraphrases the agent's answer. The same correct answer can be classified
differently across runs depending on exact wording.

**Recommendation:** Write expected facts as strings that appear verbatim in
the tool's JSON output — enum values (`"immediate_review"`), exact error
messages (`"Assess the finding before recording an analyst decision"`), or
field names. These are independent of LLM prose style and eliminate a
class of false failures.

### L-3 — System prompt presentation rules directly determine correctness scores

Q-03 and Q-05 both failed because the agent called the correct tool and
received correct data, but dropped key facts from its prose answer. The
root cause in both cases was an underspecified presentation rule in the
system prompt, not a bug in the tool or policy logic.

**Recommendation:** Treat the system prompt as first-class code. When a
correctness failure shows scope=PASS and correctness=FAIL, the first place
to look is the presentation rules in the prompt, not the tool implementation.
Enumerate presentation sub-rules explicitly (which fields to always state,
in what form) rather than relying on the LLM to infer them from a vague
"present results clearly" instruction.

### L-4 — Policy rationale text is part of the observable output

Q-03 continued failing after the prompt was improved because the policy
engine's rationale for rule U-1 was a generic phrase ("Missing local
context must not reduce priority") that didn't name the unknown fields.
The agent quoted the rationale verbatim, so fixing the prompt alone was
insufficient.

**Recommendation:** Write policy rationale strings to be self-contained and
specific. If the rationale is the only place a key fact appears, make sure
it names that fact explicitly. The rationale is not internal state — it
surfaces directly to the analyst and to any evaluation judge.

### L-5 — Multi-step tool calls require a shared server process

Questions Q-08, Q-09, Q-13, and Q-14 require `assess_finding` followed by
`record_analyst_decision` for the same finding. The `record_analyst_decision`
tool looks up the stored assessment from the SQLite repository. If `assess`
and `record` run against different server processes (different SQLite
connections), the lookup fails with "Assess the finding before recording an
analyst decision."

**Recommendation:** The eval agent opens one MCP server subprocess per
question (via `invoke()`) and shares it across all tool calls within that
question using a `contextvars.ContextVar`. Any deployment that spans tool
calls across process boundaries must use a shared persistent store rather
than the in-process SQLite default.

---

## Running the eval locally

```bash
# Start Phoenix
uv run --group eval phoenix serve &

# Run with OpenAI (agent + judge)
OPENAI_API_KEY=sk-... \
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --model openai:gpt-4o-mini \
    --judge-model openai:gpt-4o-mini \
    --fail-below-scope 1.0 \
    --fail-below-correctness 0.90

# Scope only — no API key needed (uses Ollama llama3.1:8b for the agent)
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --skip-correctness-judge \
    --fail-below-scope 1.0
```

## Directory layout

```
eval/
├── phoenix/
│   ├── agent.py              # VulnCompassAgent — LangGraph ReAct + flat @tool wrappers
│   ├── run_experiment.py     # CLI entry point
│   ├── create_dataset.py     # Upload vulncompass.csv to a Phoenix server
│   ├── datasets.yaml         # Registry: dataset name → CSV path + column names
│   ├── prompts/
│   │   └── v1.txt            # System prompt describing all four tools
│   ├── judges/
│   │   ├── correctness.py    # ClassificationEvaluator backed by Ollama or OpenAI
│   │   └── scope.py          # Span-fetch judge — reads real Phoenix traces
│   └── datasets/
│       └── vulncompass/
│           ├── evaluation.xml    # 15 gold Q&A pairs (authoritative source)
│           └── vulncompass.csv   # Flat CSV consumed by run_experiment.py
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EVAL_MODEL` | `llama3.1:8b` | Agent model. Prefix with `openai:` for ChatOpenAI. |
| `JUDGE_MODEL` | `llama3.1:8b` | Correctness judge model. Same prefix rule. |
| `OPENAI_API_KEY` | — | Required only for `openai:` prefixed models. |
| `PHOENIX_HOST` | `http://localhost:6006` | Phoenix base URL. |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama OpenAI-compat endpoint. |
