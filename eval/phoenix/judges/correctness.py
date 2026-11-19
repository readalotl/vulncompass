"""Correctness judge — LLM-as-judge that checks whether the agent's answer
contains every expected fact from the dataset row.

Uses the Phoenix 21.x ClassificationEvaluator / evaluate_dataframe API.
Defaults to Ollama (llama3.2:3b via its OpenAI-compatible endpoint) so the
judge runs without any API key. Pass JUDGE_MODEL=openai:<model> plus
OPENAI_API_KEY to use an OpenAI model instead.
"""

from __future__ import annotations

import os

import pandas as pd
from phoenix.evals import ClassificationEvaluator, LLM, evaluate_dataframe

CORRECTNESS_TEMPLATE = """\
You are evaluating whether an assistant's answer correctly addresses a
vulnerability management question.

Question:
{question}

Expected facts:
{expected_facts}

Assistant answer:
{answer}

Evaluate each expected fact separately.

For each fact, explain whether it is supported by the answer and quote the
specific words that support your decision. If it is missing, say so.

Treat equivalent wording as a match. Examples:
- "Immediate Review" and "immediate_review" are the same.
- "Accelerated Remediation" and "accelerated_remediation" are the same.
- "Routine Remediation" and "routine_remediation" are the same.
- "Proposed Closure" and "proposed_closure" are the same.
- "Investigate Applicability" and "investigate_applicability" are the same.
- "High", "high", and "high confidence" all express the same confidence level.
- "ranked first" is satisfied by "rank-1", "rank 1", "first", or "ranked first".
- "action is defer" is satisfied when the answer states the action is defer.
- A fact that is a phrase (e.g. "CVE Program record is REJECTED") is supported
  if that phrase or its clear equivalent appears in the answer.

Check the surrounding context: a phrase that is negated or contradicted does
not establish the fact.

Classify the answer as "correct" only if every expected fact is supported.
Otherwise classify it as "incorrect".
"""

# Default: llama3.1:8b via Ollama OpenAI-compat endpoint (no API key needed).
# 8b is significantly more reliable than 3b for structured classification.
_DEFAULT_JUDGE_MODEL = "llama3.1:8b"
_OLLAMA_BASE_URL = "http://localhost:11434/v1"
_OLLAMA_API_KEY = "ollama"  # Ollama ignores the key but the client requires one.


def _build_llm(judge_model: str | None = None) -> LLM:
    """Build a Phoenix LLM evaluator backend.

    Resolution order:
      1. ``judge_model`` argument (explicit override)
      2. ``JUDGE_MODEL`` env var
      3. Default: ``llama3.2:3b`` via Ollama

    Prefix with ``openai:`` to force the real OpenAI API, e.g.
    ``JUDGE_MODEL=openai:gpt-4o-mini``.
    """
    model_spec = judge_model or os.environ.get("JUDGE_MODEL", _DEFAULT_JUDGE_MODEL)

    if model_spec.startswith("openai:"):
        model_name = model_spec[len("openai:"):]
        api_key = os.environ.get("OPENAI_API_KEY", "")
        return LLM(
            provider="openai",
            model=model_name,
            sync_client_kwargs={"api_key": api_key},
            async_client_kwargs={"api_key": api_key},
        )

    # Ollama (or any OpenAI-compat local server): use provider="openai" with
    # a custom base_url pointing at the Ollama REST endpoint.
    base_url = os.environ.get("OLLAMA_BASE_URL", _OLLAMA_BASE_URL)
    return LLM(
        provider="openai",
        model=model_spec,
        sync_client_kwargs={"api_key": _OLLAMA_API_KEY, "base_url": base_url},
        async_client_kwargs={"api_key": _OLLAMA_API_KEY, "base_url": base_url},
    )


def run_correctness(
    questions: list[str],
    answers: list[str],
    expected_facts: list[list[str]],
    *,
    judge_model: str | None = None,
) -> list[dict]:
    """Score each (question, answer) pair against its expected_facts list.

    Returns a list of dicts with keys: score (0 or 1), label, explanation.
    """
    llm = _build_llm(judge_model)

    rows = []
    for q, a, facts in zip(questions, answers, expected_facts):
        facts_text = "\n".join(f"- {f}" for f in facts)
        rows.append({"question": q, "answer": a, "expected_facts": facts_text})

    df = pd.DataFrame(rows)

    evaluator = ClassificationEvaluator(
        name="correctness",
        llm=llm,
        prompt_template=CORRECTNESS_TEMPLATE,
        choices={"correct": 1, "incorrect": 0},
        include_explanation=True,
    )

    results_df = evaluate_dataframe(df, evaluators=[evaluator])

    scored = []
    for _, row in results_df.iterrows():
        # Phoenix 21.x stores the Score as a dict under "correctness_score".
        score_obj = row.get("correctness_score")
        if isinstance(score_obj, dict):
            score = int(score_obj.get("score") or 0)
            label = str(score_obj.get("label") or ("correct" if score == 1 else "incorrect"))
            explanation = str(score_obj.get("explanation") or "")
        elif score_obj is not None and hasattr(score_obj, "score"):
            # Dataclass form (older Phoenix builds).
            score = int(score_obj.score or 0)
            label = str(score_obj.label or ("correct" if score == 1 else "incorrect"))
            explanation = str(score_obj.explanation or "")
        else:
            # Flat-column fallback.
            label = str(row.get("correctness.label", "incorrect") or "incorrect")
            score = int(row.get("correctness.score", 0) or 0)
            explanation = str(row.get("correctness.explanation", "") or "")
        scored.append(
            {
                "score": score,
                "label": label,
                "explanation": explanation,
            }
        )
    return scored
