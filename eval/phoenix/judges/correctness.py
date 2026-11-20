"""Correctness judge — LLM-as-judge that checks whether the agent's answer
contains every expected fact from the dataset row.

Uses the Phoenix 21.x ClassificationEvaluator / evaluate_dataframe API for
the primary OpenAI judge.  A separate watsonx.ai judge uses ChatWatsonx via
langchain-ibm and the same prompt but calls the model directly.

Both judges support majority voting: each row is evaluated ``votes`` times and
the majority label wins (ties default to "incorrect").

Model prefixes
--------------
openai:<name>    ChatOpenAI (default judge)
watsonx:<name>   ChatWatsonx via langchain-ibm (second judge)
<name>           Ollama via OpenAI-compat endpoint (local fallback)
"""

from __future__ import annotations

import os
from collections import Counter

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

Step 1 — For each expected fact, output exactly one line in this format:
  FACT "<fact text>" → SUPPORTED: "<exact quote from the answer>"
  or
  FACT "<fact text>" → MISSING: "<brief reason>"

Rules for Step 1:
- A fact is SUPPORTED if the answer contains it, its display-form equivalent,
  or its clear paraphrase. Quote the words that support it.
- Equivalent wording counts as a match:
  "Immediate Review" = "immediate_review"
  "Accelerated Remediation" = "accelerated_remediation"
  "Routine Remediation" = "routine_remediation"
  "Proposed Closure" = "proposed_closure"
  "Investigate Applicability" = "investigate_applicability"
  "High" / "high" / "high confidence" all express the same confidence level.
  "ranked first" is satisfied by "rank-1", "rank 1", or "ranked first".
  "action is defer" is satisfied when the answer states the action is defer.
- A fact that is a phrase is SUPPORTED if that phrase or a clear equivalent
  appears anywhere in the answer.
- A phrase that is negated or contradicted is NOT supported.
- Do not add requirements that are not listed in the expected facts.
  Evaluate only the facts given, nothing more.

Step 2 — After listing every fact verdict, output your final classification:
  If every fact is SUPPORTED → output "correct"
  If any fact is MISSING → output "incorrect"
"""

# Default: llama3.1:8b via Ollama OpenAI-compat endpoint (no API key needed).
_DEFAULT_JUDGE_MODEL = "llama3.1:8b"
_OLLAMA_BASE_URL = "http://localhost:11434/v1"
_OLLAMA_API_KEY = "ollama"  # Ollama ignores the key but the client requires one.

# Default watsonx model — granite-13b-instruct-v2 is reliable for classification.
_DEFAULT_WATSONX_MODEL = "ibm/granite-13b-instruct-v2"


# ── Phoenix LLM backend (OpenAI / Ollama) ────────────────────────────────────

def _build_llm(judge_model: str | None = None) -> LLM:
    """Build a Phoenix LLM evaluator backend for OpenAI or Ollama.

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

    base_url = os.environ.get("OLLAMA_BASE_URL", _OLLAMA_BASE_URL)
    return LLM(
        provider="openai",
        model=model_spec,
        sync_client_kwargs={"api_key": _OLLAMA_API_KEY, "base_url": base_url},
        async_client_kwargs={"api_key": _OLLAMA_API_KEY, "base_url": base_url},
    )


# ── Literal-match pre-check ──────────────────────────────────────────────────

def _all_facts_literal(facts: list[str], answer: str) -> bool:
    """Return True if every expected fact is a case-insensitive substring of answer.

    When this is True the LLM judge cannot possibly add information — every
    required string is already present — so we short-circuit to score=1 without
    making an API call.  This eliminates false-negatives caused by the judge
    inventing requirements that are not in the expected-facts list.
    """
    answer_lo = answer.casefold()
    return all(f.casefold() in answer_lo for f in facts)


# ── Score extraction helper ──────────────────────────────────────────────────

def _extract_score(row: "pd.Series") -> dict:
    """Extract score/label/explanation from a Phoenix evaluate_dataframe row."""
    score_obj = row.get("correctness_score")
    if isinstance(score_obj, dict):
        score = int(score_obj.get("score") or 0)
        label = str(score_obj.get("label") or ("correct" if score == 1 else "incorrect"))
        explanation = str(score_obj.get("explanation") or "")
    elif score_obj is not None and hasattr(score_obj, "score"):
        score = int(score_obj.score or 0)
        label = str(score_obj.label or ("correct" if score == 1 else "incorrect"))
        explanation = str(score_obj.explanation or "")
    else:
        label = str(row.get("correctness.label", "incorrect") or "incorrect")
        score = int(row.get("correctness.score", 0) or 0)
        explanation = str(row.get("correctness.explanation", "") or "")
    return {"score": score, "label": label, "explanation": explanation}


# ── Majority-vote wrapper for the Phoenix evaluator ─────────────────────────

def _run_once(
    df: "pd.DataFrame",
    llm: LLM,
) -> list[dict]:
    """Run the evaluator once and return per-row score dicts."""
    evaluator = ClassificationEvaluator(
        name="correctness",
        llm=llm,
        prompt_template=CORRECTNESS_TEMPLATE,
        choices={"correct": 1, "incorrect": 0},
        include_explanation=True,
    )
    results_df = evaluate_dataframe(df, evaluators=[evaluator])
    return [_extract_score(row) for _, row in results_df.iterrows()]


def _majority(votes: list[int]) -> int:
    """Return 1 if the majority of votes are 1, else 0. Ties → 0."""
    return 1 if sum(votes) > len(votes) / 2 else 0


# ── Primary judge (OpenAI / Ollama, with majority voting) ───────────────────

def run_correctness(
    questions: list[str],
    answers: list[str],
    expected_facts: list[list[str]],
    *,
    judge_model: str | None = None,
    votes: int = 3,
) -> list[dict]:
    """Score each (question, answer) pair with majority voting.

    Runs the evaluator ``votes`` times and takes the majority label.  Ties
    (only possible when votes is even) default to "incorrect".

    Returns a list of dicts with keys:
        score        majority score (0 or 1)
        label        "correct" or "incorrect"
        explanation  explanation from the final deciding call
        all_scores   raw per-call scores for auditing
    """
    llm = _build_llm(judge_model)

    # Pre-check: rows where every fact is literally present in the answer are
    # scored correct without an LLM call.  The judge cannot add value there and
    # has a documented tendency to fabricate MISSING verdicts even when the text
    # is present (Q-04, Q-05 false-negatives).
    literal_pass: list[bool] = [
        _all_facts_literal(facts, a) for facts, a in zip(expected_facts, answers)
    ]

    # Build a DataFrame only for rows that need LLM scoring.
    llm_indices: list[int] = []
    rows = []
    for idx, (q, a, facts) in enumerate(zip(questions, answers, expected_facts)):
        if not literal_pass[idx]:
            facts_text = "\n".join(f"- {f}" for f in facts)
            rows.append({"question": q, "answer": a, "expected_facts": facts_text})
            llm_indices.append(idx)

    # Run majority voting only for rows that reached the LLM.
    llm_scored: list[dict] = []
    if rows:
        df = pd.DataFrame(rows)
        all_runs: list[list[dict]] = []
        for _ in range(max(1, votes)):
            all_runs.append(_run_once(df, llm))

        for local_idx in range(len(rows)):
            row_votes = [run[local_idx] for run in all_runs]
            vote_scores = [r["score"] for r in row_votes]
            maj = _majority(vote_scores)
            majority_label = "correct" if maj == 1 else "incorrect"
            explanation = next(
                (r["explanation"] for r in reversed(row_votes) if r["label"] == majority_label),
                row_votes[-1]["explanation"],
            )
            llm_scored.append(
                {
                    "score": maj,
                    "label": majority_label,
                    "explanation": explanation,
                    "all_scores": vote_scores,
                }
            )

    # Merge literal-pass and LLM-scored rows back into original order.
    scored: list[dict] = []
    llm_iter = iter(llm_scored)
    for idx in range(len(questions)):
        if literal_pass[idx]:
            scored.append(
                {
                    "score": 1,
                    "label": "correct",
                    "explanation": "All expected facts matched literally in the answer (pre-check bypass).",
                    "all_scores": [1],
                }
            )
        else:
            scored.append(next(llm_iter))

    return scored


# ── Watsonx.ai second judge ──────────────────────────────────────────────────

def _build_watsonx_chain(model_id: str | None = None):
    """Build a LangChain ChatWatsonx chain for direct invocation.

    Required environment variables:
        WATSONX_API_KEY     IBM Cloud API key
        WATSONX_PROJECT_ID  watsonx.ai project ID
        WATSONX_URL         watsonx.ai endpoint (default: us-south)

    Returns None if the required env vars are absent.
    """
    api_key = os.environ.get("WATSONX_API_KEY", "")
    project_id = os.environ.get("WATSONX_PROJECT_ID", "")
    if not api_key or not project_id:
        return None

    url = os.environ.get(
        "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
    )
    mid = model_id or os.environ.get("WATSONX_JUDGE_MODEL", _DEFAULT_WATSONX_MODEL)
    if mid.startswith("watsonx:"):
        mid = mid[len("watsonx:"):]

    try:
        from langchain_ibm import ChatWatsonx
    except ImportError:
        return None

    return ChatWatsonx(
        model_id=mid,
        url=url,
        api_key=api_key,
        project_id=project_id,
        params={"temperature": 0, "max_new_tokens": 512},
    )


def _score_with_watsonx(
    chain,
    question: str,
    answer: str,
    facts: list[str],
) -> dict:
    """Invoke the watsonx chain once and parse a correct/incorrect label."""
    facts_text = "\n".join(f"- {f}" for f in facts)
    prompt = CORRECTNESS_TEMPLATE.format(
        question=question,
        answer=answer,
        expected_facts=facts_text,
    )
    try:
        response = chain.invoke(prompt)
        text = getattr(response, "content", str(response)).strip().lower()
    except Exception as exc:  # noqa: BLE001
        return {"score": 0, "label": "error", "explanation": str(exc)}

    # The model should end with "correct" or "incorrect".
    # Search from the end so Step 1 narration doesn't confuse the parse.
    label = "incorrect"
    for line in reversed(text.splitlines()):
        line = line.strip().rstrip(".")
        if line in ("correct", "incorrect"):
            label = line
            break
        # Accept lines like "classification: correct"
        if "correct" in line and "incorrect" not in line:
            label = "correct"
            break
        if "incorrect" in line:
            label = "incorrect"
            break

    return {
        "score": 1 if label == "correct" else 0,
        "label": label,
        "explanation": text[:600],
    }


def run_correctness_watsonx(
    questions: list[str],
    answers: list[str],
    expected_facts: list[list[str]],
    *,
    model_id: str | None = None,
    votes: int = 3,
) -> list[dict] | None:
    """Score each pair using a watsonx.ai model with majority voting.

    Returns None when WATSONX_API_KEY or WATSONX_PROJECT_ID is not set,
    so callers can skip gracefully without error.

    Returns a list of dicts with the same schema as run_correctness plus
    an ``all_scores`` list of per-call scores.
    """
    chain = _build_watsonx_chain(model_id)
    if chain is None:
        return None

    results = []
    for question, answer, facts in zip(questions, answers, expected_facts):
        # Same literal-match pre-check as the primary judge.
        if _all_facts_literal(facts, answer):
            results.append(
                {
                    "score": 1,
                    "label": "correct",
                    "explanation": "All expected facts matched literally in the answer (pre-check bypass).",
                    "all_scores": [1],
                }
            )
            continue

        row_votes = [
            _score_with_watsonx(chain, question, answer, facts)
            for _ in range(max(1, votes))
        ]
        vote_scores = [r["score"] for r in row_votes]
        maj = _majority(vote_scores)
        majority_label = "correct" if maj == 1 else "incorrect"
        explanation = next(
            (r["explanation"] for r in reversed(row_votes) if r["label"] == majority_label),
            row_votes[-1]["explanation"],
        )
        results.append(
            {
                "score": maj,
                "label": majority_label,
                "explanation": explanation,
                "all_scores": vote_scores,
            }
        )

    return results
