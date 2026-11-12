"""CLI — upload a named dataset from datasets.yaml to a running Phoenix instance.

Usage:
    uv run --group eval python eval/phoenix/create_dataset.py vulncompass

Environment variables:
    PHOENIX_HOST   Phoenix base URL (default: http://localhost:6006)

The dataset is uploaded with the name from datasets.yaml and printed dataset ID
can be passed to run_experiment.py with --dataset-id.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pandas as pd
import phoenix as px
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATASETS_YAML = Path(__file__).parent / "datasets.yaml"


def load_registry() -> dict:
    with _DATASETS_YAML.open() as fh:
        return yaml.safe_load(fh)["datasets"]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Upload a dataset to Phoenix.")
    parser.add_argument("dataset", help="Dataset name as defined in datasets.yaml")
    parser.add_argument(
        "--phoenix-host",
        default=os.environ.get("PHOENIX_HOST", "http://localhost:6006"),
        help="Phoenix base URL (default: http://localhost:6006)",
    )
    args = parser.parse_args(argv)

    registry = load_registry()
    if args.dataset not in registry:
        print(f"ERROR: unknown dataset '{args.dataset}'. Known: {list(registry)}", file=sys.stderr)
        sys.exit(1)

    entry = registry[args.dataset]
    csv_path = _REPO_ROOT / entry["csv"]
    if not csv_path.exists():
        print(f"ERROR: CSV not found at {csv_path}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from {csv_path}")

    client = px.Client(endpoint=args.phoenix_host)
    dataset = client.upload_dataset(
        dataframe=df,
        dataset_name=args.dataset,
        input_keys=[entry["input_column"]],
        output_keys=[entry["expected_facts_column"]],
        metadata_keys=[entry.get("id_column", "id")],
    )
    print(f"Dataset uploaded: name={dataset.name!r}  id={dataset.id!r}")
    print(f"\nRun the experiment with:")
    print(f"  uv run --group eval python eval/phoenix/run_experiment.py {args.dataset} --dataset-id {dataset.id}")


if __name__ == "__main__":
    main()
