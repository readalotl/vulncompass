"""Local SQLite persistence for findings, snapshots, and analyst decisions."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from vulncompass.config import settings
from vulncompass.models import Assessment, EvidenceSnapshot, FindingInput


class Repository:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (settings.data_dir / "vulncompass.db")

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                finding_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                finding_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                assessed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_finding
                ON snapshots(finding_id, id DESC);
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                action TEXT NOT NULL,
                rationale TEXT NOT NULL,
                analyst_id TEXT,
                modified_recommendation TEXT,
                decision_json TEXT NOT NULL,
                reviewed_at TEXT NOT NULL
            );
            """
        )
        return connection

    def save_assessment(self, finding: FindingInput, assessment: Assessment) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessments(
                    finding_id, cve_id, finding_json, assessment_json, assessed_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    cve_id=excluded.cve_id,
                    finding_json=excluded.finding_json,
                    assessment_json=excluded.assessment_json,
                    assessed_at=excluded.assessed_at
                """,
                (
                    finding.finding_id,
                    finding.cve_id,
                    finding.model_dump_json(),
                    assessment.model_dump_json(),
                    assessment.assessed_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO snapshots(finding_id, snapshot_json, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    finding.finding_id,
                    assessment.evidence.model_dump_json(),
                    assessment.evidence.retrieved_at.isoformat(),
                ),
            )

    def get_assessment(self, finding_id: str) -> tuple[FindingInput, Assessment] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT finding_json, assessment_json
                FROM assessments WHERE finding_id=?
                """,
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        return (
            FindingInput.model_validate_json(row["finding_json"]),
            Assessment.model_validate_json(row["assessment_json"]),
        )

    def latest_snapshot(self, finding_id: str) -> EvidenceSnapshot | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT snapshot_json FROM snapshots
                WHERE finding_id=? ORDER BY id DESC LIMIT 1
                """,
                (finding_id,),
            ).fetchone()
        return (
            EvidenceSnapshot.model_validate_json(row["snapshot_json"])
            if row
            else None
        )

    def save_decision(self, record: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO decisions(
                    finding_id, action, rationale, analyst_id,
                    modified_recommendation, decision_json, reviewed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["finding_id"],
                    record["action"],
                    record["rationale"],
                    record.get("analyst_id"),
                    record.get("modified_recommendation"),
                    json.dumps(record, separators=(",", ":")),
                    record["reviewed_at"],
                ),
            )


repository = Repository()
