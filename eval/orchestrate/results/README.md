# Orchestrate Evaluation Results

This directory holds TSV evidence files exported from the watsonx Orchestrate
evaluation UI and committed as human-readable history.

---

## Storage policy

Raw timestamped output directories produced by `orchestrate evaluations evaluate`
(e.g. `evaluate_2026-11-17_10-30-00/`) are **git-ignored** via
`eval/orchestrate/results/*/` in `.gitignore`. They can be large and are
regenerated on demand.

Selected TSV exports are **committed directly in this directory** as the
authoritative evidence record. Each committed file represents a named run and
carries the full per-test-case metric table exported from the Orchestrate UI.

---

## Run history

| File | Date | Status | Notes |
|------|------|--------|-------|
| [`run_2026-11-17_results.tsv`](run_2026-11-17_results.tsv) | 2026-11-17 | Historical | Initial run. `policy_fidelity` score 0 on TC-01 (KEV test) due to missing `agreement` field in tool response. |
| [`run_2026-11-17b_results.tsv`](run_2026-11-17b_results.tsv) | 2026-11-17 | Intermediate | Extra/incorrect tool calls on TC-01, TC-02, TC-03, TC-04. `tool_call_precision` 0.6, mean `rubric_mean_score` 0.75. |
| [`run_2026-11-17c_results.tsv`](run_2026-11-17c_results.tsv) | 2026-11-17 | **Accepted final** | All six test cases pass. `policy_fidelity` 1.0, `rubric_mean_score` 1.0, `tool_call_precision` 1.0. See [summary](run_2026-11-17c_summary.md). |

### Code revision evaluated
Likely **`a9c54c6`** (docstring hardening for `assess_finding` and
`detect_material_changes`, `agreement` field present in fixture response).

### Evidence commit
**`4e3d1fa`** — commit that added the TSV exports to the repository.

---

## To run a new evaluation

```bash
orchestrate evaluations evaluate \
  --config eval/orchestrate/eval_config.yaml
```

Export the results TSV from the Orchestrate UI and commit it here as
`run_<date>[_suffix]_results.tsv`. Update this README's run history table.
