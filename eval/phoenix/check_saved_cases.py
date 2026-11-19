"""Check saved answers and negative examples with the per-fact judge."""

import json
import sys
from pathlib import Path

from eval.phoenix.judges.fact_audit import run_correctness


path = Path(sys.argv[1])
cases = json.loads(path.read_text(encoding="utf-8"))

# The saved artifact contains the older Q-11 criteria. Use the revised
# user-facing criteria for this new evaluator.
for case in cases:
    if case["id"] == "Q-11":
        case["expected_facts"] = [
            "proposed_closure",
            "vendor and VulnCompass priority bands differ",
            "the difference does not establish that the vendor is wrong",
        ]

negative_cases = [
    {
        "id": "NEG-KEV",
        "question": "Is the CVE listed in CISA KEV?",
        "answer": "No. The CVE is not listed in CISA KEV.",
        "expected_facts": ["The CVE is listed in CISA KEV"],
    },
    {
        "id": "NEG-VENDOR",
        "question": "What does the disagreement establish?",
        "answer": "The disagreement proves the vendor is wrong.",
        "expected_facts": [
            "the difference does not establish that the vendor is wrong"
        ],
    },
]

all_cases = cases + negative_cases

results = run_correctness(
    [case["question"] for case in all_cases],
    [case["answer"] for case in all_cases],
    [case["expected_facts"] for case in all_cases],
    judge_model="openai:gpt-4o-mini",
)

for case, result in zip(all_cases, results):
    print(f"\n{case['id']}: {result['label']}")
    print(json.dumps(result["fact_results"], indent=2, ensure_ascii=False))
