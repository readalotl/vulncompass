"""Persistence backends for findings, snapshots, and analyst decisions.

SQLite (default)
    Zero-configuration. Safe for single-analyst or demo use. One writer at a
    time — concurrent writes from multiple processes may block or serialize.

Postgres (multi-analyst)
    Set DATABASE_URL=postgresql://user:pass@host:5432/dbname to activate.
    Requires ``psycopg2-binary`` (or ``psycopg2``) to be installed.
    Concurrent writes are safe; the schema is created automatically on first
    connection.

Both backends expose the same ``Repository`` interface so no other module
needs to know which storage engine is in use.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from vulncompass.config import settings
from vulncompass.models import Assessment, EvidenceSnapshot, FindingInput

# ---------------------------------------------------------------------------
# Shared DDL — column names and types are valid for both SQLite and Postgres.
# ---------------------------------------------------------------------------
_DDL = """
CREATE TABLE IF NOT EXISTS assessments (
    finding_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    assessment_json TEXT NOT NULL,
    assessed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id {serial} PRIMARY KEY,
    finding_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_finding
    ON snapshots(finding_id, id DESC);
CREATE TABLE IF NOT EXISTS decisions (
    id {serial} PRIMARY KEY,
    finding_id TEXT NOT NULL,
    action TEXT NOT NULL,
    rationale TEXT NOT NULL,
    analyst_id TEXT,
    modified_recommendation TEXT,
    decision_json TEXT NOT NULL,
    reviewed_at TEXT NOT NULL
);
"""

_SQLITE_DDL = _DDL.format(serial="INTEGER AUTOINCREMENT")
_PG_DDL = _DDL.format(serial="SERIAL")


# ---------------------------------------------------------------------------
# SQLite backend (default, zero-dependency)
# ---------------------------------------------------------------------------


class Repository:
    """SQLite-backed repository. Safe for single-analyst and demo deployments."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (settings.data_dir / "vulncompass.db")

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        # SQLite AUTOINCREMENT syntax differs from Postgres SERIAL — use the
        # SQLite-specific DDL here.
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
            EvidenceSnapshot.model_validate_json(row["snapshot_json"]) if row else None
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


# ---------------------------------------------------------------------------
# Postgres backend (multi-analyst, concurrent-safe)
# ---------------------------------------------------------------------------


class PostgresRepository:
    """Postgres-backed repository for multi-analyst, concurrent-safe deployments.

    Requires ``psycopg2-binary`` (or ``psycopg2``).
    Activated automatically when ``DATABASE_URL`` is set in the environment.

    The schema is created on first connection — no migration tool required for
    an initial deploy. For schema evolution, use Alembic or a migration script.
    """

    def __init__(self, database_url: str) -> None:
        self._url = database_url
        self._schema_created = False

    def _connect(self):  # type: ignore[return]
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2-binary is required for Postgres storage. "
                "Install it with:  pip install psycopg2-binary"
            ) from exc
        conn = psycopg2.connect(self._url)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        if not self._schema_created:
            with conn.cursor() as cur:
                cur.execute(_PG_DDL)
            conn.commit()
            self._schema_created = True
        return conn

    def save_assessment(self, finding: FindingInput, assessment: Assessment) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO assessments(
                        finding_id, cve_id, finding_json, assessment_json, assessed_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        cve_id=EXCLUDED.cve_id,
                        finding_json=EXCLUDED.finding_json,
                        assessment_json=EXCLUDED.assessment_json,
                        assessed_at=EXCLUDED.assessed_at
                    """,
                    (
                        finding.finding_id,
                        finding.cve_id,
                        finding.model_dump_json(),
                        assessment.model_dump_json(),
                        assessment.assessed_at.isoformat(),
                    ),
                )
                cur.execute(
                    """
                    INSERT INTO snapshots(finding_id, snapshot_json, created_at)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        finding.finding_id,
                        assessment.evidence.model_dump_json(),
                        assessment.evidence.retrieved_at.isoformat(),
                    ),
                )

    def get_assessment(self, finding_id: str) -> tuple[FindingInput, Assessment] | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT finding_json, assessment_json "
                    "FROM assessments WHERE finding_id=%s",
                    (finding_id,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return (
            FindingInput.model_validate_json(row["finding_json"]),
            Assessment.model_validate_json(row["assessment_json"]),
        )

    def latest_snapshot(self, finding_id: str) -> EvidenceSnapshot | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT snapshot_json FROM snapshots "
                    "WHERE finding_id=%s ORDER BY id DESC LIMIT 1",
                    (finding_id,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return EvidenceSnapshot.model_validate_json(row["snapshot_json"])

    def save_decision(self, record: dict[str, Any]) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO decisions(
                        finding_id, action, rationale, analyst_id,
                        modified_recommendation, decision_json, reviewed_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
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


# ---------------------------------------------------------------------------
# Factory — returns the right backend based on DATABASE_URL
# ---------------------------------------------------------------------------


def get_repository(database_url: str = "") -> Repository | PostgresRepository:
    """Return a SQLite or Postgres repository depending on ``DATABASE_URL``.

    Uses ``settings.database_url`` if ``database_url`` is not supplied.
    SQLite is always the fallback when no URL is configured.
    """
    url = database_url or settings.database_url
    if url:
        return PostgresRepository(url)
    return Repository()


# Module-level singleton used by service.py:
#   from vulncompass.storage import repository
repository: Repository | PostgresRepository = get_repository()
