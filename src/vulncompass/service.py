"""Application services used by the MCP tool registration layer."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

from vulncompass.evidence import get_evidence
from vulncompass.models import (
    AnalystDecisionInput,
    Assessment,
    ChangeDetectionRequest,
    EvidenceMode,
    EvidenceSnapshot,
    FindingInput,
    PrioritizeRequest,
)
from vulncompass.policy import assess_policy, priority_sort_key
from vulncompass.storage import Repository, repository


async def assess_finding_service(
    finding: FindingInput,
    mode: EvidenceMode = EvidenceMode.FIXTURE,
    *,
    repo: Repository = repository,
) -> Assessment:
    evidence = await get_evidence(finding.cve_id, mode)
    assessment = assess_policy(finding, evidence)
    repo.save_assessment(finding, assessment)
    return assessment


async def prioritize_findings_service(
    request: PrioritizeRequest,
    *,
    repo: Repository = repository,
) -> dict[str, Any]:
    submitted_findings = list(request.findings)
    submitted_count = len(submitted_findings)
    errors: list[dict[str, str]] = []
    if request.csv_text:
        reader = csv.DictReader(io.StringIO(request.csv_text))
        for row_number, row in enumerate(reader, start=2):
            submitted_count += 1
            if len(submitted_findings) >= 200:
                errors.append(
                    {
                        "finding_id": f"csv-row-{row_number}",
                        "error": "input_limit_exceeded",
                        "hint": "Only the first 200 CSV findings are processed.",
                    }
                )
                break
            cleaned = {key: value for key, value in row.items() if key is not None}
            for key in (
                "vendor_severity",
                "vendor_risk_score",
                "vendor_priority",
                "vendor_evidence_timestamp",
            ):
                if cleaned.get(key) == "":
                    cleaned[key] = None
            for key in (
                "applicability",
                "internet_exposure",
                "mission_criticality",
                "compensating_controls",
            ):
                if cleaned.get(key) == "":
                    cleaned[key] = "unknown"
            try:
                submitted_findings.append(FindingInput.model_validate(cleaned))
            except ValueError:
                errors.append(
                    {
                        "finding_id": cleaned.get("finding_id")
                        or f"csv-row-{row_number}",
                        "error": "invalid_finding",
                        "hint": f"Correct the required fields in CSV row {row_number}.",
                    }
                )

    unique: dict[str, FindingInput] = {}
    duplicates: list[str] = []
    for finding in submitted_findings:
        if finding.finding_id in unique:
            duplicates.append(finding.finding_id)
        else:
            unique[finding.finding_id] = finding

    assessments: list[Assessment] = []
    for finding in unique.values():
        try:
            assessments.append(
                await assess_finding_service(finding, request.mode, repo=repo)
            )
        except (ValueError, OSError) as exc:
            errors.append(
                {
                    "finding_id": finding.finding_id,
                    "error": "evidence_unavailable",
                    "hint": str(exc),
                }
            )

    assessments.sort(key=priority_sort_key)
    ranked = []
    for rank, assessment in enumerate(assessments[: request.limit], start=1):
        ranked.append(
            {
                "rank": rank,
                "finding_id": assessment.finding_id,
                "cve_id": assessment.cve_id,
                "vendor_priority": assessment.vendor_recommendation.get("priority"),
                "vulncompass_recommendation": assessment.vulncompass_recommendation,
                "agreement": assessment.agreement,
                "queue_reason": assessment.rationale[0],
                "confidence": assessment.confidence,
                "missing_information": assessment.missing_information,
                "review_status": assessment.review_status,
            }
        )
    return {
        "ranked_findings": ranked,
        "duplicates": duplicates,
        "invalid_or_incomplete": errors,
        "processing_summary": {
            "submitted": submitted_count,
            "unique": len(unique),
            "assessed": len(assessments),
            "returned": len(ranked),
            "errors": len(errors),
        },
    }


def _value(snapshot: EvidenceSnapshot, path: tuple[str, ...]) -> Any:
    current: Any = snapshot.model_dump(mode="json")
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def compare_snapshots(
    previous: EvidenceSnapshot, current: EvidenceSnapshot, finding_id: str | None
) -> dict[str, Any]:
    fields = {
        "kev.listed": ("kev", "listed"),
        "kev.date_added": ("kev", "date_added"),
        "kev.due_date": ("kev", "due_date"),
        "kev.required_action": ("kev", "required_action"),
        "nvd.status": ("nvd", "status"),
        "nvd.last_modified": ("nvd", "last_modified"),
        "nvd.cvss.vector": ("nvd", "cvss", "vector"),
        "nvd.configurations": ("nvd", "configurations"),
        "vulnrichment.ssvc": ("vulnrichment", "ssvc"),
    }
    changes = []
    for name, path in fields.items():
        old = _value(previous, path)
        new = _value(current, path)
        if old != new:
            changes.append(
                {
                    "field": name,
                    "old_value": old,
                    "new_value": new,
                    "source": name.split(".", 1)[0],
                    "reason": (
                        f"{name} changed and may alter applicability, urgency, "
                        "or confidence."
                    ),
                    "policy_rule_triggered": "CHANGE-1",
                }
            )
    return {
        "finding_id": finding_id,
        "cve_id": current.cve_id,
        "previous_retrieved_at": previous.retrieved_at,
        "current_retrieved_at": current.retrieved_at,
        "changes": changes,
        "material_change_detected": bool(changes),
        "requires_analyst_rereview": bool(changes),
    }


async def detect_material_changes_service(
    request: ChangeDetectionRequest,
    *,
    repo: Repository = repository,
) -> dict[str, Any]:
    stored = repo.get_assessment(request.finding_id) if request.finding_id else None
    cve_id = request.cve_id or (stored[0].cve_id if stored else None)
    if cve_id is None:
        raise ValueError("Provide cve_id or a finding_id with a stored assessment.")

    previous = request.previous_snapshot
    if previous is None and request.finding_id:
        previous = repo.latest_snapshot(request.finding_id)
    if previous is None:
        raise ValueError("No previous evidence snapshot is available for comparison.")

    current = request.current_snapshot or await get_evidence(cve_id, request.mode)
    return compare_snapshots(previous, current, request.finding_id)


def record_analyst_decision_service(
    decision: AnalystDecisionInput,
    *,
    repo: Repository = repository,
) -> dict[str, Any]:
    stored = repo.get_assessment(decision.finding_id)
    if stored is None:
        raise ValueError("Assess the finding before recording an analyst decision.")
    _, assessment = stored
    if decision.action.value == "modify" and decision.modified_recommendation is None:
        raise ValueError("modified_recommendation is required when action is modify.")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    record = {
        "finding_id": decision.finding_id,
        "cve_id": assessment.cve_id,
        "action": decision.action.value,
        "rationale": decision.rationale,
        "analyst_id": decision.analyst_id,
        "vendor_recommendation": assessment.vendor_recommendation,
        "vulncompass_recommendation": assessment.vulncompass_recommendation.value,
        "modified_recommendation": (
            decision.modified_recommendation.value
            if decision.modified_recommendation
            else None
        ),
        "evidence_snapshot": assessment.evidence.model_dump(mode="json"),
        "policy_version": assessment.policy_version,
        "reviewed_at": reviewed_at,
        "review_status": "DECIDED",
    }
    repo.save_decision(record)
    return record
