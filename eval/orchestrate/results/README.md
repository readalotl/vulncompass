# Orchestrate Evaluation Results

This directory is populated by `orchestrate evaluations evaluate` when run
with `eval/orchestrate/eval_config.yaml`. It is git-ignored.

Each run produces a timestamped subdirectory, e.g.:

```
results/
└── evaluate_2026-11-17_10-30-00/
    ├── config.yml          # full resolved config for reproducibility
    ├── results.json        # per-test-case scores and reasoning
    └── summary.json        # aggregate metrics across all test cases
```

To run:

```bash
orchestrate evaluations evaluate \
  --config eval/orchestrate/eval_config.yaml
```
