"""Transparent, deterministic recommendation and confidence rules."""

from __future__ import annotations

from vulncompass.models import (
    Applicability,
    Assessment,
    Confidence,
    ControlStatus,
    Criticality,
    EvidenceSnapshot,
    Exposure,
    FindingInput,
    Recommendation,
)

POLICY_VERSION = "2026.11.2"


def _is_kev(evidence: EvidenceSnapshot) -> bool:
    return bool(evidence.kev and evidence.kev.get("listed") is True)


def _missing(finding: FindingInput) -> list[str]:
    missing: list[str] = []
    if finding.applicability is Applicability.UNKNOWN:
        missing.append("applicability")
    if finding.internet_exposure is Exposure.UNKNOWN:
        missing.append("internet_exposure")
    if finding.mission_criticality is Criticality.UNKNOWN:
        missing.append("mission_criticality")
    if finding.compensating_controls is ControlStatus.UNKNOWN:
        missing.append("compensating_controls")
    return missing


def _conflicts(evidence: EvidenceSnapshot) -> list[str]:
    conflicts: list[str] = []
    status = (evidence.nvd or {}).get("status", "")
    program_state = (evidence.cve_program or {}).get("state", "")
    if _is_kev(evidence) and str(status).upper() in {"REJECTED", "DISPUTED"}:
        conflicts.append(f"CISA KEV lists the CVE while NVD status is {status}.")
    if str(program_state).upper() == "REJECTED":
        if str(status).upper() not in {"", "REJECTED"}:
            conflicts.append(
                "The CVE Program record is REJECTED while NVD reports "
                f"status {status}."
            )
        if _is_kev(evidence):
            conflicts.append(
                "The CVE Program record is REJECTED while CISA KEV lists the CVE."
            )
        if (evidence.nuclei or {}).get("template_available") is True:
            conflicts.append(
                "The CVE Program record is REJECTED while the community Nuclei "
                "index contains a template."
            )
    return conflicts


def _vendor_level(priority: str | None, severity: str | None) -> int | None:
    value = (priority or severity or "").lower()
    if any(token in value for token in ("critical", "immediate", "urgent")):
        return 0
    if any(token in value for token in ("high", "accelerated")):
        return 1
    if any(token in value for token in ("moderate", "medium", "routine")):
        return 2
    if any(token in value for token in ("low", "informational", "close")):
        return 3
    return None


def _recommendation_level(recommendation: Recommendation) -> int:
    return {
        Recommendation.IMMEDIATE_REVIEW: 0,
        Recommendation.ACCELERATED_REMEDIATION: 1,
        Recommendation.INVESTIGATE_APPLICABILITY: 1,
        Recommendation.ROUTINE_REMEDIATION: 2,
        Recommendation.PROPOSED_CLOSURE: 3,
    }[recommendation]


def assess_policy(finding: FindingInput, evidence: EvidenceSnapshot) -> Assessment:
    missing = _missing(finding)
    conflicts = _conflicts(evidence)
    kev = _is_kev(evidence)
    rules: list[str] = []
    rationale: list[str] = []

    if finding.applicability is Applicability.CONFIRMED_NOT_AFFECTED:
        recommendation = Recommendation.PROPOSED_CLOSURE
        rules.append("A-4")
        rationale.append(
            "Applicability is locally reported as confirmed not affected; "
            "closure still requires analyst review."
        )
    elif kev and finding.applicability in {
        Applicability.CONFIRMED_AFFECTED,
        Applicability.LIKELY_AFFECTED,
    }:
        recommendation = Recommendation.IMMEDIATE_REVIEW
        rules.append("K-1")
        rationale.append("CISA KEV listing requires immediate analyst review.")
        if finding.applicability is Applicability.LIKELY_AFFECTED:
            rationale.append("Applicability remains likely rather than confirmed.")
    elif kev:
        recommendation = Recommendation.INVESTIGATE_APPLICABILITY
        rules.append("K-2")
        rationale.append(
            "CISA KEV lists the CVE, but local applicability is unknown."
        )
    elif (
        finding.applicability is Applicability.CONFIRMED_AFFECTED
        and finding.internet_exposure is Exposure.PUBLIC
        and finding.mission_criticality is Criticality.HIGH
    ):
        recommendation = Recommendation.ACCELERATED_REMEDIATION
        rules.append("L-1")
        rationale.append(
            "The asset is reported affected, publicly exposed, and mission critical."
        )
    elif finding.applicability is Applicability.UNKNOWN or missing:
        recommendation = Recommendation.INVESTIGATE_APPLICABILITY
        rules.append("U-1")
        rationale.append("Missing local context must not reduce priority.")
    else:
        recommendation = Recommendation.ROUTINE_REMEDIATION
        rules.append("R-1")
        rationale.append("No higher-priority deterministic condition applies.")

    if (evidence.nuclei or {}).get("template_available") is True:
        rationale.append(
            "The community Nuclei index contains a detection template; this is "
            "supporting evidence only and does not prove weaponization, active "
            "exploitation, or local applicability."
        )

    unavailable = [
        source
        for source in evidence.unavailable_sources
        if source != "nuclei_templates"
    ]
    if conflicts or finding.applicability is Applicability.UNKNOWN or unavailable:
        confidence = Confidence.LOW
    elif missing or finding.applicability is Applicability.LIKELY_AFFECTED:
        confidence = Confidence.MODERATE
    else:
        confidence = Confidence.HIGH

    vendor_level = _vendor_level(finding.vendor_priority, finding.vendor_severity)
    agreement = (
        None
        if vendor_level is None
        else vendor_level == _recommendation_level(recommendation)
    )
    if agreement is True:
        comparison = "The vendor and VulnCompass priority bands agree."
    elif agreement is False:
        comparison = (
            "The priority bands differ because VulnCompass applies the listed "
            "public evidence and local policy rules; this does not establish "
            "that the vendor is wrong."
        )
    else:
        comparison = "The vendor priority could not be mapped to a comparison band."

    return Assessment(
        finding_id=finding.finding_id,
        cve_id=finding.cve_id,
        vendor_recommendation={
            "severity": finding.vendor_severity,
            "risk_score": finding.vendor_risk_score,
            "priority": finding.vendor_priority,
            "evidence_timestamp": finding.vendor_evidence_timestamp,
        },
        vulncompass_recommendation=recommendation,
        agreement=agreement,
        comparison_explanation=comparison,
        confidence=confidence,
        policy_rules=rules,
        rationale=rationale,
        missing_information=missing,
        source_conflicts=conflicts,
        evidence=evidence,
        policy_version=POLICY_VERSION,
    )


def priority_sort_key(assessment: Assessment) -> tuple[int, int, str]:
    priority = {
        Recommendation.IMMEDIATE_REVIEW: 0,
        Recommendation.ACCELERATED_REMEDIATION: 1,
        Recommendation.INVESTIGATE_APPLICABILITY: 2,
        Recommendation.ROUTINE_REMEDIATION: 3,
        Recommendation.PROPOSED_CLOSURE: 4,
    }[assessment.vulncompass_recommendation]
    confidence = {
        Confidence.LOW: 0,
        Confidence.MODERATE: 1,
        Confidence.HIGH: 2,
    }[assessment.confidence]
    return priority, confidence, assessment.finding_id
