"""Validated contracts shared by VulnCompass tools and services."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvidenceMode(str, Enum):
    FIXTURE = "fixture"
    CACHED = "cached"
    LIVE = "live"


class Applicability(str, Enum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    LIKELY_AFFECTED = "likely_affected"
    UNKNOWN = "unknown"
    CONFIRMED_NOT_AFFECTED = "confirmed_not_affected"


class Exposure(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class Criticality(str, Enum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class ControlStatus(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Recommendation(str, Enum):
    IMMEDIATE_REVIEW = "immediate_review"
    ACCELERATED_REMEDIATION = "accelerated_remediation"
    ROUTINE_REMEDIATION = "routine_remediation"
    INVESTIGATE_APPLICABILITY = "investigate_applicability"
    PROPOSED_CLOSURE = "proposed_closure"


class Confidence(str, Enum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class ReviewStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    DECIDED = "DECIDED"


class DecisionAction(str, Enum):
    APPROVE = "approve"
    MODIFY = "modify"
    REJECT = "reject"
    DEFER = "defer"
    REQUEST_INVESTIGATION = "request_investigation"


class FindingInput(StrictModel):
    finding_id: str = Field(min_length=1, max_length=128)
    source_vendor: str = Field(min_length=1, max_length=128)
    source_finding_id: str = Field(min_length=1, max_length=256)
    cve_id: str = Field(description="Public CVE identifier, for example CVE-2024-3094.")
    asset_id: str = Field(min_length=1, max_length=256)
    vendor_severity: str | None = Field(default=None, max_length=64)
    vendor_risk_score: float | str | None = None
    vendor_priority: str | None = Field(default=None, max_length=64)
    vendor_evidence_timestamp: datetime | None = None
    applicability: Applicability = Applicability.UNKNOWN
    internet_exposure: Exposure = Exposure.UNKNOWN
    mission_criticality: Criticality = Criticality.UNKNOWN
    compensating_controls: ControlStatus = ControlStatus.UNKNOWN

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        normalized = value.upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            raise ValueError("cve_id must match CVE-YYYY-NNNN")
        return normalized


class Provenance(StrictModel):
    source: str
    record_url: str
    retrieved_at: datetime
    as_of: datetime | None = None


class EvidenceSnapshot(StrictModel):
    cve_id: str
    retrieved_at: datetime = Field(default_factory=utc_now)
    mode: EvidenceMode
    cve_program: dict[str, Any] | None = None
    nvd: dict[str, Any] | None = None
    kev: dict[str, Any] | None = None
    vulnrichment: dict[str, Any] | None = None
    nuclei: dict[str, Any] | None = None
    unavailable_sources: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)


class Assessment(StrictModel):
    finding_id: str
    cve_id: str
    vendor_recommendation: dict[str, Any]
    vulncompass_recommendation: Recommendation
    agreement: bool | None
    comparison_explanation: str
    confidence: Confidence
    policy_rules: list[str]
    rationale: list[str]
    missing_information: list[str]
    source_conflicts: list[str]
    evidence: EvidenceSnapshot
    policy_version: str
    review_status: ReviewStatus = ReviewStatus.PENDING_REVIEW
    assessed_at: datetime = Field(default_factory=utc_now)


class PrioritizeRequest(StrictModel):
    findings: list[FindingInput] = Field(default_factory=list, max_length=200)
    csv_text: str | None = Field(
        default=None,
        max_length=1_000_000,
        description="Optional generic finding CSV supplied as local text.",
    )
    mode: EvidenceMode = EvidenceMode.FIXTURE
    limit: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def require_one_input_format(self) -> PrioritizeRequest:
        if bool(self.findings) == bool(self.csv_text):
            raise ValueError("Provide either findings or csv_text, but not both.")
        return self


class ChangeDetectionRequest(StrictModel):
    finding_id: str | None = Field(default=None, max_length=128)
    cve_id: str | None = None
    previous_snapshot: EvidenceSnapshot | None = None
    current_snapshot: EvidenceSnapshot | None = None
    mode: EvidenceMode = EvidenceMode.FIXTURE

    @field_validator("cve_id")
    @classmethod
    def validate_optional_cve_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            raise ValueError("cve_id must match CVE-YYYY-NNNN")
        return normalized


class AnalystDecisionInput(StrictModel):
    finding_id: str = Field(min_length=1, max_length=128)
    action: DecisionAction
    rationale: str = Field(min_length=1, max_length=4000)
    analyst_id: str | None = Field(
        default=None,
        max_length=128,
        description="Optional local pseudonym; never sent to public sources.",
    )
    modified_recommendation: Recommendation | None = None
