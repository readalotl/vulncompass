# watsonx Orchestrate Evaluation

End-to-end behavioral evaluation of the VulnCompass agent using the
[watsonx Orchestrate ADK evaluation framework](https://developer.watson-orchestrate.ibm.com/evaluate/evaluate).

This directory is **distinct from `eval/phoenix/`**, which uses Arize Phoenix as
the experiment platform. Use this directory when evaluating the agent deployed
inside watsonx Orchestrate.

---

## Directory layout

```
eval/orchestrate/
├── eval_config.yaml          # Orchestrate evaluation config (RubricEvaluation judges)
├── test_cases/               # Ground-truth test cases in ADK JSON format
│   ├── TC-01_assess_kev_immediate_review.json
│   ├── TC-02_prioritize_findings_queue.json
│   ├── TC-03_detect_material_changes.json
│   ├── TC-04_record_analyst_decision.json
│   └── TC-05_adversarial_scope_boundary.json
├── judges/                   # Judge prompt source files (also inlined in eval_config.yaml)
│   ├── policy_fidelity.md
│   └── human_review_safety.md
└── results/                  # Populated by evaluation runs (git-ignored)
    └── README.md
```

---

## Test cases

| ID | Tool exercised | Story |
|----|---------------|-------|
| TC-01 | `assess_finding` | KEV-listed CVE, confirmed affected → `immediate_review` |
| TC-02 | `prioritize_findings` | Two-finding CSV backlog → ranked queue |
| TC-03 | `detect_material_changes` | Check for evidence changes on CVE-2099-0001 |
| TC-04 | `assess_finding` → `record_analyst_decision` | Assess then approve — two-step decision |
| TC-05 | `record_analyst_decision` (adversarial) | Scope-boundary: attempt autonomous closure without prior assessment |

---

## Judges

Both judges are defined in [`eval_config.yaml`](eval_config.yaml) under
`operator_configs.RubricEvaluation.custom_criteria` and are also readable as
standalone Markdown in [`judges/`](judges/).

| Judge | What it checks |
|-------|---------------|
| `policy_fidelity` | Accurate policy rule descriptions (K-1/K-2/L-1/A-4/U-1/R-1), recommendation matches tool output, vendor vs VulnCompass separation, Nuclei scope limits, KEV catalog naming, no scope overreach |
| `human_review_safety` | Mandatory human oversight preserved — no autonomous closure, remediation, risk acceptance, or scanner writes; PENDING_REVIEW not bypassed |

Both produce a binary pass/fail per test case. The overall `RubricEvaluation`
score is the average across all criteria.

---

## Prerequisites

- ADK >= 2.9.0 (`pip install --upgrade ibm-watsonx-orchestrate`)
- Active Orchestrate environment (`orchestrate env activate`)
- `vulncompass_agent` and `vulncompass` toolkit already imported
  (see [`deploy/ibm/local-mcp-toolkit/README.md`](../../deploy/ibm/local-mcp-toolkit/README.md))

---

## Running the evaluation

```bash
# From the repo root:
orchestrate evaluations evaluate \
  --config eval/orchestrate/eval_config.yaml
```

Results are written to `eval/orchestrate/results/` (git-ignored).

For SaaS or on-premises, update `auth_config.url` and `auth_config.tenant_name`
in [`eval_config.yaml`](eval_config.yaml) before running.
