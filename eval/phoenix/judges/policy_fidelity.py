"""Policy-fidelity judge — LLM-as-judge that checks whether the agent's answer
accurately reflects VulnCompass policy rules and tool results.

Scores 1.0 (pass), 0.5 (partial), or 0.0 (fail) using Phoenix 21.x
ClassificationEvaluator with three labelled choices mapped to numeric values.
Shares the same LLM-backend factory as the correctness judge.
"""

from __future__ import annotations

import os

import pandas as pd
from phoenix.evals import ClassificationEvaluator, LLM, evaluate_dataframe

POLICY_FIDELITY_TEMPLATE = """\
Evaluate the agent response for fidelity to VulnCompass policy and tool results.
Do not grade writing style, formatting, or verbosity.

Assign exactly one score:

1.0 — PASS
The response satisfies every applicable requirement below.

0.5 — PARTIAL
The core recommendation is correct, but there is one minor omission or
imprecision that does not change the policy meaning and does not overstate
evidence or capabilities.

0.0 — FAIL
The response incorrectly describes a policy trigger, contradicts the tool
result, invents evidence, overstates VulnCompass capabilities, or makes any
other material policy error.

Requirements:

1. Policy rules must be described accurately:
   - K-1: The CVE is CISA KEV-listed and local applicability is confirmed
     affected or likely affected. Public exposure and mission criticality are
     not required for K-1.
   - K-2: The CVE is CISA KEV-listed, but local applicability is unknown.
   - L-1: Applicability is confirmed affected, the asset is publicly exposed,
     and mission criticality is high, when a higher-priority KEV rule does not
     apply.
   - A-4: Applicability is confirmed not affected, resulting in a proposed
     closure.
   - U-1: Applicability or required local context is unknown or missing,
     resulting in investigation.
   - R-1: No higher-priority rule applies, resulting in routine remediation.

2. The recommendation, confidence, policy rule, missing information, source
   conflicts, and review status must match the VulnCompass tool result when
   those values are available.

3. Vendor severity or priority must remain separate from the VulnCompass
   recommendation. The response must not claim that they agree unless the tool
   result explicitly reports agreement.

4. Nuclei template metadata is supporting evidence only. It is not proof that
   the asset is vulnerable, exploitation has occurred, the vulnerability is
   weaponized, or the finding is applicable.

5. CISA KEV must be described as the Known Exploited Vulnerabilities catalog.
   Do not describe a KEV entry as merely a "known exploit vector."

6. The response must preserve human-review boundaries. It must not claim that
   VulnCompass scanned or verified the host, confirmed patch availability,
   performed remediation, accepted risk, closed a finding, or wrote information
   back to another system.

7. Do not invent, expand, or reinterpret a policy rule beyond the definition
   above.

Question asked to the assistant:
{question}

Actual assistant answer:
{answer}

Return the numeric score and one concise explanation. If the score is below
1.0, identify the exact incorrect statement or missing requirement.
Classify the answer as "pass", "partial", or "fail".
"""

_DEFAULT_JUDGE_MODEL = "llama3.1:8b"
_OLLAMA_BASE_URL = "http://localhost:11434/v1"
_OLLAMA_API_KEY = "ollama"


def _build_llm(judge_model: str | None = None) -> LLM:
    """Build a Phoenix LLM evaluator backend (same resolution order as correctness.py)."""
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


def run_policy_fidelity(
    questions: list[str],
    answers: list[str],
    *,
    judge_model: str | None = None,
) -> list[dict]:
    """Score each (question, answer) pair for VulnCompass policy fidelity.

    Returns a list of dicts with keys: score (1.0, 0.5, or 0.0), label, explanation.
    """
    llm = _build_llm(judge_model)

    rows = [{"question": q, "answer": a} for q, a in zip(questions, answers)]
    df = pd.DataFrame(rows)

    evaluator = ClassificationEvaluator(
        name="policy_fidelity",
        llm=llm,
        prompt_template=POLICY_FIDELITY_TEMPLATE,
        choices={"pass": 1.0, "partial": 0.5, "fail": 0.0},
        include_explanation=True,
    )

    results_df = evaluate_dataframe(df, evaluators=[evaluator])

    scored = []
    for _, row in results_df.iterrows():
        score_obj = row.get("policy_fidelity_score")
        if isinstance(score_obj, dict):
            score = float(score_obj.get("score") or 0.0)
            label = str(score_obj.get("label") or ("pass" if score == 1.0 else "fail"))
            explanation = str(score_obj.get("explanation") or "")
        elif score_obj is not None and hasattr(score_obj, "score"):
            score = float(score_obj.score or 0.0)
            label = str(score_obj.label or ("pass" if score == 1.0 else "fail"))
            explanation = str(score_obj.explanation or "")
        else:
            label = str(row.get("policy_fidelity.label", "fail") or "fail")
            score = float(row.get("policy_fidelity.score", 0.0) or 0.0)
            explanation = str(row.get("policy_fidelity.explanation", "") or "")
        scored.append({"score": score, "label": label, "explanation": explanation})
    return scored
