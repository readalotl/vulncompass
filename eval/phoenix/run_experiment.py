"""CLI — run the VulnCompass eval experiment against a Phoenix dataset.

Usage:
    # Run against the local CSV directly (no Phoenix upload needed):
    uv run --group eval python eval/phoenix/run_experiment.py vulncompass

    # Run against a previously uploaded Phoenix dataset by ID:
    uv run --group eval python eval/phoenix/run_experiment.py vulncompass \\
        --dataset-id <id-from-create_dataset.py>

    # Point at a remote Phoenix instance:
    uv run --group eval python eval/phoenix/run_experiment.py vulncompass \\
        --phoenix-host https://my-phoenix.example.com

    # Skip the LLM correctness judge (no API key required):
    uv run --group eval python eval/phoenix/run_experiment.py vulncompass \\
        --skip-correctness-judge

Environment variables:
    PHOENIX_HOST     Phoenix base URL (default: http://localhost:6006)
    PHOENIX_API_KEY  API key for authenticated Phoenix instances (optional).
                     Set this when Phoenix returns 401 on span export or queries.
    OPENAI_API_KEY   Only needed when --model is "openai:<model-name>"
    EVAL_MODEL       Model for the agent (default: llama3.1:8b via Ollama)
                     Prefix with "openai:" to use ChatOpenAI instead,
                     e.g. EVAL_MODEL=openai:gpt-4o-mini
"""

from __future__ import annotations

# ── sys.path fix: must come before any eval.* imports ────────────────────────
# eval/phoenix/run_experiment.py lives two levels below the repo root.
# Without this, `import eval.phoenix.*` fails because the repo root is not on
# sys.path when the script is invoked directly with `python eval/phoenix/...`.
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import os
import time

import pandas as pd
import yaml

_DATASETS_YAML = Path(__file__).parent / "datasets.yaml"


def _setup_tracing(phoenix_host: str):
    """Register OpenInference tracing to Phoenix. Must be called before the agent is built.

    Returns the tracer so callers can start spans and read trace IDs.
    """
    from phoenix.otel import register
    from openinference.instrumentation.langchain import LangChainInstrumentor

    headers = {}
    api_key = os.environ.get("PHOENIX_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    tracer_provider = register(
        endpoint=f"{phoenix_host.rstrip('/')}/v1/traces",
        project_name="vulncompass-eval",
        headers=headers,
    )
    LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
    return tracer_provider


def load_registry() -> dict:
    with _DATASETS_YAML.open() as fh:
        return yaml.safe_load(fh)["datasets"]


def load_dataset_local(entry: dict) -> pd.DataFrame:
    csv_path = _REPO_ROOT / entry["csv"]
    if not csv_path.exists():
        print(f"ERROR: CSV not found at {csv_path}", file=sys.stderr)
        sys.exit(1)
    return pd.read_csv(csv_path)


def load_dataset_phoenix(dataset_id: str, phoenix_host: str) -> pd.DataFrame:
    import phoenix as px
    client = px.Client(endpoint=phoenix_host)
    dataset = client.get_dataset(id=dataset_id)
    return dataset.as_dataframe()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the VulnCompass eval experiment.")
    parser.add_argument("dataset", help="Dataset name as defined in datasets.yaml")
    parser.add_argument("--dataset-id", default=None, help="Phoenix dataset ID (optional)")
    parser.add_argument(
        "--phoenix-host",
        default=os.environ.get("PHOENIX_HOST", "http://localhost:6006"),
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("EVAL_MODEL", "llama3.1:8b"),
        help=(
            "Model for the agent. Default: llama3.1:8b (Ollama, no API key). "
            "Prefix with 'openai:' to use ChatOpenAI, e.g. openai:gpt-4o-mini."
        ),
    )
    parser.add_argument(
        "--skip-correctness-judge",
        action="store_true",
        help="Skip the LLM-as-judge correctness step.",
    )
    parser.add_argument(
        "--judge-model",
        default=os.environ.get("JUDGE_MODEL", "llama3.1:8b"),
        help=(
            "Model for the correctness judge. Default: llama3.2:3b (Ollama, no API key). "
            "Prefix with 'openai:' to use ChatOpenAI, e.g. openai:gpt-4o-mini."
        ),
    )
    parser.add_argument(
        "--fail-below-scope",
        type=float,
        default=None,
        metavar="RATE",
        help=(
            "Exit 1 if the scope pass rate is strictly below RATE (0.0–1.0). "
            "Example: --fail-below-scope 1.0 fails unless every question called a tool."
        ),
    )
    parser.add_argument(
        "--fail-below-correctness",
        type=float,
        default=None,
        metavar="RATE",
        help=(
            "Exit 1 if the LLM correctness pass rate is strictly below RATE (0.0–1.0). "
            "Informational by default; use --fail-below-tool-checks for a hard gate. "
            "Ignored when --skip-correctness-judge is set."
        ),
    )
    parser.add_argument(
        "--fail-below-tool-checks",
        type=float,
        default=None,
        metavar="RATE",
        help=(
            "Exit 1 if the deterministic tool-result check pass rate is strictly "
            "below RATE (0.0–1.0). Example: --fail-below-tool-checks 1.0 fails "
            "unless every tool returned the expected structured fields."
        ),
    )
    parser.add_argument(
        "--skip-tool-checks",
        action="store_true",
        help="Skip the deterministic tool-result checks (useful when Phoenix is unavailable).",
    )
    args = parser.parse_args(argv)

    if args.model.startswith("openai:") and not os.environ.get("OPENAI_API_KEY"):
        print(
            f"ERROR: agent model '{args.model}' requires OPENAI_API_KEY but it is not set.\n"
            "\n"
            "    export OPENAI_API_KEY=sk-...\n"
            "\n"
            "Or drop the 'openai:' prefix to use the default Ollama model instead:\n"
            "    --model llama3.2:3b",
            file=sys.stderr,
        )
        sys.exit(1)

    registry = load_registry()
    if args.dataset not in registry:
        print(
            f"ERROR: unknown dataset '{args.dataset}'. Known: {list(registry)}",
            file=sys.stderr,
        )
        sys.exit(1)

    entry = registry[args.dataset]

    # Load dataset.
    if args.dataset_id:
        print(f"Loading dataset {args.dataset_id!r} from Phoenix…")
        df = load_dataset_phoenix(args.dataset_id, args.phoenix_host)
    else:
        print("Loading dataset from local CSV (use create_dataset.py to upload to Phoenix)…")
        df = load_dataset_local(entry)

    q_col = entry["input_column"]
    facts_col = entry["expected_facts_column"]
    checks_col = entry.get("expected_tool_checks_column")
    questions: list[str] = df[q_col].tolist()
    raw_facts: list[str] = df[facts_col].tolist()
    expected_facts: list[list[str]] = [
        [f.strip() for f in str(rf).split("|")] for rf in raw_facts
    ]
    # Load per-row structured tool checks if the column exists in both the
    # YAML registry and the CSV.
    expected_tool_checks: list[dict] = []
    if checks_col and checks_col in df.columns:
        for raw in df[checks_col].tolist():
            try:
                val = json.loads(str(raw)) if str(raw).strip() not in ("", "nan") else {}
                expected_tool_checks.append(val if isinstance(val, dict) else {})
            except (json.JSONDecodeError, TypeError):
                expected_tool_checks.append({})
    else:
        expected_tool_checks = [{} for _ in questions]

    print(f"Dataset: {len(questions)} questions")
    print(f"Agent model:  {args.model}")
    print(f"Judge model:  {args.judge_model}")
    print(f"Phoenix:      {args.phoenix_host}\n")

    # Setup tracing BEFORE building the agent so every LangChain call is traced.
    tracer_provider = _setup_tracing(args.phoenix_host)

    # Import agent AFTER instrumentation is active (instrumentor patches LangChain at import).
    from eval.phoenix.agent import VulnCompassAgent
    agent = VulnCompassAgent(model=args.model)

    # Grab a tracer to create root spans that carry a stable trace_id per question.
    from opentelemetry import trace as otel_trace
    tracer = otel_trace.get_tracer("vulncompass-eval")

    # ── Run the agent on each question ───────────────────────────────────────
    answers: list[str] = []
    trace_ids: list[str | None] = []

    for i, question in enumerate(questions, start=1):
        row_id = df["id"].iloc[i - 1] if "id" in df.columns else str(i)
        print(f"[{i:02d}/{len(questions)}] {row_id} — invoking agent…", end=" ", flush=True)
        try:
            # Wrap each question in a root span so all child spans share one trace_id.
            with tracer.start_as_current_span(f"question-{row_id}") as span:
                ctx = span.get_span_context()
                # Format as 32-char hex string (Phoenix's context.trace_id column format).
                tid = format(ctx.trace_id, "032x") if ctx and ctx.is_valid else None
                trace_ids.append(tid)
                answer = agent.invoke(question)
            answers.append(answer)
            print("OK")
        except Exception as exc:  # noqa: BLE001
            answers.append(f"ERROR: {exc}")
            trace_ids.append(None)
            print(f"ERROR: {exc}")

    # Allow the OTLP exporter a moment to flush spans to Phoenix before querying.
    # CI runners are slower than local machines; 15 s is enough for all 10 traces.
    print("\nWaiting for traces to flush to Phoenix…", flush=True)
    time.sleep(15)

    # ── Scope judge (trace-based, no LLM needed) ─────────────────────────────
    # fetch_spans_for_trace() is called per trace_id to pull real Phoenix spans.
    from eval.phoenix.judges.scope import run_scope
    scope_results = run_scope(
        [[] for _ in answers],
        trace_ids=trace_ids,
        phoenix_host=args.phoenix_host,
        project_name="vulncompass-eval",
    )

    # ── Tool-result judge (deterministic, no LLM) ────────────────────────────
    if not args.skip_tool_checks:
        print("\nRunning deterministic tool-result checks…")
        from eval.phoenix.judges.tool_result import run_tool_checks
        tool_check_results = run_tool_checks(
            expected_tool_checks,
            trace_ids,
            phoenix_host=args.phoenix_host,
            project_name="vulncompass-eval",
        )
    else:
        print("\nSkipping tool-result checks (--skip-tool-checks).")
        tool_check_results = [
            {"score": None, "checks": [], "explanation": "skipped"}
        ] * len(answers)

    # ── Correctness judge (LLM-as-judge, informational) ──────────────────────
    if not args.skip_correctness_judge:
        print(f"\nRunning correctness judge ({args.judge_model})…")
        from eval.phoenix.judges.correctness import run_correctness
        correctness_results = run_correctness(
            questions, answers, expected_facts, judge_model=args.judge_model
        )
    else:
        print("\nSkipping correctness judge (--skip-correctness-judge).")
        correctness_results = [
            {"score": None, "label": "skipped", "explanation": ""}
        ] * len(answers)

    # Save enough detail to investigate failed correctness cases.
    failed_cases = []
    for i, result in enumerate(correctness_results):
        if result.get("score") == 0:
            failed_cases.append(
                {
                    "id": str(df["id"].iloc[i]),
                    "question": questions[i],
                    "expected_facts": expected_facts[i],
                    "answer": answers[i],
                    "judge_label": result.get("label"),
                    "judge_explanation": result.get("explanation"),
                    "literal_matches": {
                        fact: fact.casefold() in answers[i].casefold()
                        for fact in expected_facts[i]
                    },
                    "trace_id": trace_ids[i],
                }
            )

    Path("eval-failures.json").write_text(
        json.dumps(failed_cases, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── Print results table ──────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print(f"{'ID':<8} {'Scope':>6} {'ToolChk':>8} {'LLM':>5}  Answer (first 60 chars)")
    print("-" * 80)
    scope_scores = []
    tool_check_scores = []
    correctness_scores = []
    for i, (a, sr, tr, cr) in enumerate(
        zip(answers, scope_results, tool_check_results, correctness_results)
    ):
        row_id = df["id"].iloc[i] if "id" in df.columns else str(i + 1)
        scope_label = "PASS" if sr["score"] == 1 else "FAIL"
        tc_label = {1: "PASS", 0: "FAIL", -1: " N/A", None: "SKIP"}.get(tr["score"], "FAIL")
        corr_label = {1: "PASS", 0: "FAIL", None: " -- "}.get(cr["score"], "FAIL")
        print(
            f"{row_id!s:<8} {scope_label:>6}  {tc_label:>7} {corr_label:>5}  "
            f"{a[:60].strip()!r}"
        )
        scope_scores.append(sr["score"] or 0)
        if tr["score"] is not None and tr["score"] != -1:
            tool_check_scores.append(tr["score"])
        if cr["score"] is not None:
            correctness_scores.append(cr["score"])

    print("=" * 80)
    n = len(scope_scores)
    scope_mean = sum(scope_scores) / n if n else 0.0
    tc_mean = sum(tool_check_scores) / len(tool_check_scores) if tool_check_scores else None
    corr_mean = sum(correctness_scores) / len(correctness_scores) if correctness_scores else None
    print(f"\nScope (tool called):              {scope_mean:.0%}  ({sum(scope_scores)}/{n})")
    if tc_mean is not None:
        print(
            f"Tool-result checks (deterministic): {tc_mean:.0%}"
            f"  ({sum(tool_check_scores)}/{len(tool_check_scores)})"
        )
    if corr_mean is not None:
        print(
            f"Correctness (LLM judge, info only): {corr_mean:.0%}"
            f"  ({sum(correctness_scores)}/{len(correctness_scores)})"
        )
    print(f"\nTraces logged to Phoenix project 'vulncompass-eval' at {args.phoenix_host}")

    # ── Threshold gates (exit 1 on regression) ───────────────────────────────
    # Tool-result checks are deterministic and form the hard gate.
    # LLM correctness is informational; --fail-below-correctness is kept for
    # backward compatibility but should not be used as the primary gate.
    failed = False
    if args.fail_below_scope is not None and scope_mean < args.fail_below_scope:
        print(
            f"\nFAIL: scope pass rate {scope_mean:.0%} is below threshold "
            f"{args.fail_below_scope:.0%} (--fail-below-scope).",
            file=sys.stderr,
        )
        failed = True
    if (
        args.fail_below_tool_checks is not None
        and not args.skip_tool_checks
        and tc_mean is not None
        and tc_mean < args.fail_below_tool_checks
    ):
        print(
            f"\nFAIL: tool-result check pass rate {tc_mean:.0%} is below threshold "
            f"{args.fail_below_tool_checks:.0%} (--fail-below-tool-checks).",
            file=sys.stderr,
        )
        failed = True
    if (
        args.fail_below_correctness is not None
        and not args.skip_correctness_judge
        and corr_mean is not None
        and corr_mean < args.fail_below_correctness
    ):
        print(
            f"\nFAIL: LLM correctness pass rate {corr_mean:.0%} is below threshold "
            f"{args.fail_below_correctness:.0%} (--fail-below-correctness).",
            file=sys.stderr,
        )
        failed = True
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
