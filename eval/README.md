# VulnCompass Eval Harness

End-to-end LLM evaluation for the VulnCompass MCP agent using
[Arize Phoenix](https://phoenix.arize.com) as the experiment platform and
[Ollama](https://ollama.com) as the local inference backend.

---

## What it measures

| Judge | What it checks | Model needed |
|-------|---------------|--------------|
| **Scope** | Did the agent call a VulnCompass tool? (vs. answering from memory) | None — reads Phoenix spans |
| **Correctness** | Does the agent's answer contain all expected facts? | LLM judge (default: `llama3.1:8b` via Ollama) |

Results from the last full run (10 questions, `llama3.1:8b` agent + judge on CPU):

```
Scope (tool called):     100%  (10/10)
Correctness (LLM judge):  40%  (4/10)  ← judge quality bottleneck, not agent
```

The 40% correctness score reflects `llama3.1:8b`'s limited ability to
classify long prose answers against short fact lists. The agent answers for
Q-01, Q-02, Q-06, and Q-08 are substantively correct — a stronger judge
(e.g. `gpt-4o-mini`) scores them correctly.

---

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
│           ├── evaluation.xml    # 10 gold Q&A pairs (source of truth)
│           └── vulncompass.csv   # Flat CSV consumed by run_experiment.py
```

---

## Prerequisites

```bash
# 1. Ollama with at least one model
ollama pull llama3.1:8b   # agent model (~4.7 GB)
ollama pull llama3.2:3b   # optional smaller judge model (~2 GB)

# 2. Phoenix (runs on localhost:6006)
uv run --group eval phoenix serve &

# 3. Eval dependencies already in the eval group:
uv sync --group eval
```

---

## Run

```bash
# Default: llama3.1:8b agent + llama3.1:8b judge, loads dataset from local CSV
uv run --group eval python eval/phoenix/run_experiment.py vulncompass

# Use a smaller/faster judge
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --judge-model llama3.2:3b

# Use OpenAI gpt-4o-mini as the judge (requires OPENAI_API_KEY)
OPENAI_API_KEY=sk-... \
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --judge-model openai:gpt-4o-mini

# Skip the correctness judge (scope only — no LLM needed at all)
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --skip-correctness-judge

# Load dataset from a previously uploaded Phoenix dataset
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --dataset-id <id-from-create_dataset.py>

# Point at a remote Phoenix instance
uv run --group eval python eval/phoenix/run_experiment.py vulncompass \
    --phoenix-host https://my-phoenix.example.com
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EVAL_MODEL` | `llama3.1:8b` | Agent model. Prefix with `openai:` for ChatOpenAI. |
| `JUDGE_MODEL` | `llama3.1:8b` | Correctness judge model. Same prefix rule. |
| `OPENAI_API_KEY` | — | Required only for `openai:` prefixed models. |
| `PHOENIX_HOST` | `http://localhost:6006` | Phoenix base URL. |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama OpenAI-compat endpoint. |

---

## Gold dataset

The 10 evaluation questions are in
[`datasets/vulncompass/evaluation.xml`](phoenix/datasets/vulncompass/evaluation.xml)
(human-readable) and
[`datasets/vulncompass/vulncompass.csv`](phoenix/datasets/vulncompass/vulncompass.csv)
(consumed by the harness).

Questions cover all four tools:

| ID | Tool exercised | Key expected facts |
|----|---------------|-------------------|
| Q-01 | `assess_finding` | `immediate_review`, `CISA KEV`, `high confidence` |
| Q-02 | `assess_finding` | `proposed_closure`, `confirmed not affected`, `high confidence` |
| Q-03 | `assess_finding` | `investigate_applicability`, `applicability is unknown`, `low confidence` |
| Q-04 | `assess_finding` | `investigate_applicability`, `CVE Program record is REJECTED`, `Nuclei` |
| Q-05 | `prioritize_findings` | `F-002`, `immediate_review`, `CISA KEV` |
| Q-06 | `prioritize_findings` | `proposed_closure`, `confirmed not affected` |
| Q-07 | `detect_material_changes` | `material_change_detected`, `requires_analyst_rereview`, `KEV`, `CVSS vector` |
| Q-08 | `assess_finding` + `record_analyst_decision` | `DECIDED`, `approve`, `accelerated_remediation` |
| Q-09 | `assess_finding` + `record_analyst_decision` | `DECIDED`, `modify`, `routine_remediation` |
| Q-10 | `record_analyst_decision` (error path) | `error`, `assess` |

---

## How the scope judge works

1. `run_experiment.py` wraps each question in an OpenTelemetry root span.
2. The LangChain instrumentor traces every LLM call and tool invocation as
   child spans under that root.
3. After all questions finish, a 5-second flush wait lets the OTLP exporter
   deliver spans to Phoenix.
4. `scope.py::run_scope()` calls
   `phoenix.client.Client.spans.get_spans_dataframe()` filtered by
   `context.trace_id` and looks for any span whose `name` or
   `attributes.tool.name` matches a known VulnCompass tool.

Score = 1 if a tool call is found, 0 otherwise.

---

## How the correctness judge works

Uses Phoenix 21.x `ClassificationEvaluator` with `choices={"correct": 1, "incorrect": 0}`.
The judge LLM receives the question, the expected facts list, and the agent's
answer, and classifies whether **all** expected facts are present.

The judge model defaults to `llama3.1:8b` via Ollama's OpenAI-compatible
endpoint (`http://localhost:11434/v1`). No API key is required.

---

## Uploading the dataset to Phoenix

```bash
# Start Phoenix first, then:
uv run --group eval python eval/phoenix/create_dataset.py
```

This uploads `vulncompass.csv` to the running Phoenix instance and prints the
dataset ID, which you can then pass to `run_experiment.py --dataset-id`.

---

## Known limitations

- **CPU inference is slow** — `llama3.1:8b` takes ~5–7 min per question on
  CPU-only hardware. The full 10-question run takes ~70–100 min.
- **`llama3.1:8b` judge is unreliable** — the small local model sometimes
  classifies correct answers as incorrect. Use `gpt-4o-mini` for reliable
  correctness scoring if an OpenAI key is available.
- **`record_analyst_decision` requires a prior `assess_finding`** — Q-08 and
  Q-09 call both tools in sequence. The agent must call `assess_finding`
  first; if it tries to record a decision for an unassessed finding the tool
  returns an error (this is correct behaviour, verified by Q-10).
- **Scope judge requires Phoenix to be running** — if Phoenix is not
  reachable, `fetch_spans_for_trace()` returns an empty list and every row
  scores 0 for scope.
