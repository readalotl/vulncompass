from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulncompass import evidence
from vulncompass.models import (
    AnalystDecisionInput,
    Applicability,
    ChangeDetectionRequest,
    DecisionAction,
    EvidenceMode,
    EvidenceSnapshot,
    FindingInput,
    PrioritizeRequest,
    Recommendation,
)
from vulncompass.service import (
    assess_finding_service,
    detect_material_changes_service,
    prioritize_findings_service,
    record_analyst_decision_service,
)
from vulncompass.storage import Repository


def finding(**updates) -> FindingInput:
    values = {
        "finding_id": "F-001",
        "source_vendor": "synthetic-vendor",
        "source_finding_id": "V-9182",
        "cve_id": "CVE-2099-0001",
        "asset_id": "ASSET-SECRET-001",
        "vendor_severity": "High",
        "vendor_risk_score": 742,
        "vendor_priority": "High",
        "applicability": "confirmed_affected",
        "internet_exposure": "public",
        "mission_criticality": "high",
        "compensating_controls": "absent",
    }
    values.update(updates)
    return FindingInput.model_validate(values)


@pytest.mark.asyncio
async def test_kev_assessment_requires_immediate_human_review(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    result = await assess_finding_service(finding(), repo=repo)
    assert result.vulncompass_recommendation is Recommendation.IMMEDIATE_REVIEW
    assert result.review_status.value == "PENDING_REVIEW"
    assert result.policy_rules == ["K-1"]
    assert result.evidence.kev["listed"] is True


@pytest.mark.asyncio
async def test_confirmed_not_affected_proposes_closure(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    result = await assess_finding_service(
        finding(applicability=Applicability.CONFIRMED_NOT_AFFECTED), repo=repo
    )
    assert result.vulncompass_recommendation is Recommendation.PROPOSED_CLOSURE
    assert result.review_status.value == "PENDING_REVIEW"


@pytest.mark.asyncio
async def test_priority_queue_is_bounded_and_reports_duplicates(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    request = PrioritizeRequest(
        findings=[
            finding(),
            finding(),
            finding(
                finding_id="F-002",
                cve_id="CVE-2099-0002",
                vendor_priority="Moderate",
            ),
        ],
        limit=1,
    )
    result = await prioritize_findings_service(request, repo=repo)
    assert result["duplicates"] == ["F-001"]
    assert len(result["ranked_findings"]) == 1
    assert result["ranked_findings"][0]["finding_id"] == "F-001"


@pytest.mark.asyncio
async def test_priority_queue_accepts_csv_and_reports_bad_rows(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    header = (
        "finding_id,source_vendor,source_finding_id,cve_id,asset_id,"
        "vendor_priority,applicability,internet_exposure,mission_criticality,"
        "compensating_controls"
    )
    good = (
        "F-CSV-1,synthetic,V-1,CVE-2099-0002,ASSET-1,Moderate,"
        "confirmed_affected,internal,moderate,present"
    )
    bad = (
        "F-CSV-2,synthetic,V-2,not-a-cve,ASSET-2,High,"
        "unknown,unknown,unknown,unknown"
    )
    csv_text = "\n".join((header, good, bad))
    result = await prioritize_findings_service(
        PrioritizeRequest(csv_text=csv_text), repo=repo
    )
    assert result["processing_summary"]["submitted"] == 2
    assert result["processing_summary"]["assessed"] == 1
    assert result["invalid_or_incomplete"][0]["finding_id"] == "F-CSV-2"


@pytest.mark.asyncio
async def test_material_change_detects_kev_addition() -> None:
    timestamp = datetime.now(timezone.utc)
    previous = EvidenceSnapshot(
        cve_id="CVE-2099-0001",
        mode=EvidenceMode.FIXTURE,
        retrieved_at=timestamp,
        kev={"listed": False},
    )
    current = previous.model_copy(update={"kev": {"listed": True}})
    result = await detect_material_changes_service(
        ChangeDetectionRequest(
            cve_id="CVE-2099-0001",
            previous_snapshot=previous,
            current_snapshot=current,
        )
    )
    assert result["material_change_detected"] is True
    assert result["requires_analyst_rereview"] is True
    assert result["changes"][0]["field"] == "kev.listed"


@pytest.mark.asyncio
async def test_material_change_detects_cve_program_and_nuclei_updates() -> None:
    timestamp = datetime.now(timezone.utc)
    previous = EvidenceSnapshot(
        cve_id="CVE-2099-0002",
        mode=EvidenceMode.FIXTURE,
        retrieved_at=timestamp,
        cve_program={"state": "PUBLISHED", "date_updated": "2099-01-01"},
        nuclei={"template_available": False},
    )
    current = previous.model_copy(
        update={
            "cve_program": {
                "state": "REJECTED",
                "date_updated": "2099-01-02",
            },
            "nuclei": {
                "template_available": True,
                "template_path": "http/cves/2099/CVE-2099-0002.yaml",
            },
        }
    )
    result = await detect_material_changes_service(
        ChangeDetectionRequest(
            cve_id="CVE-2099-0002",
            previous_snapshot=previous,
            current_snapshot=current,
        )
    )
    changed_fields = {change["field"] for change in result["changes"]}
    assert "cve_program.state" in changed_fields
    assert "cve_program.date_updated" in changed_fields
    assert "nuclei.template_available" in changed_fields
    assert result["requires_analyst_rereview"] is True


@pytest.mark.asyncio
async def test_analyst_decision_is_local_and_preserves_evidence(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    await assess_finding_service(finding(), repo=repo)
    record = record_analyst_decision_service(
        AnalystDecisionInput(
            finding_id="F-001",
            action=DecisionAction.APPROVE,
            rationale="Validated during fixture demonstration.",
            analyst_id="analyst-pseudonym",
        ),
        repo=repo,
    )
    assert record["review_status"] == "DECIDED"
    assert record["evidence_snapshot"]["cve_id"] == "CVE-2099-0001"


@pytest.mark.asyncio
async def test_live_requests_never_include_organizational_fields(
    monkeypatch, tmp_path
) -> None:
    calls: list[dict] = []

    async def fake_fetch(base_url, path, **kwargs):
        calls.append({"base_url": base_url, "path": path, **kwargs})
        if base_url == evidence.MITRE_CVE_BASE:
            return {
                "cveMetadata": {"state": "PUBLISHED"},
                "containers": {"cna": {}},
            }
        if base_url == evidence.NVD_BASE:
            return {"vulnerabilities": []}
        if base_url == evidence.CISA_FEED_BASE:
            return {"catalogVersion": "test", "vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_fetch_text(base_url, path, **kwargs):
        calls.append({"base_url": base_url, "path": path, **kwargs})
        return (
            '{"ID":"CVE-2099-0001","Info":{"Name":"Synthetic",'
            '"Severity":"high","Classification":{"CVSSScore":"8.0"}},'
            '"file_path":"http/cves/2099/CVE-2099-0001.yaml"}\n'
        )

    monkeypatch.setattr(evidence, "fetch_public_json", fake_fetch)
    monkeypatch.setattr(evidence, "fetch_public_text", fake_fetch_text)
    monkeypatch.setattr(evidence, "_kev_catalog_cache", None)
    monkeypatch.setattr(evidence, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(evidence.settings, "data_dir", tmp_path)
    repo = Repository(tmp_path / "test.db")
    await assess_finding_service(finding(), EvidenceMode.LIVE, repo=repo)

    serialized = repr(calls)
    assert "CVE-2099-0001" in serialized
    for secret in (
        "ASSET-SECRET-001",
        "F-001",
        "synthetic-vendor",
        "mission_criticality",
    ):
        assert secret not in serialized


def test_cve_program_normalization_preserves_cna_assertions() -> None:
    result = evidence._normalize_cve_program(
        {
            "cveMetadata": {
                "state": "PUBLISHED",
                "assignerShortName": "Example CNA",
                "dateUpdated": "2026-11-09T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {"lang": "en", "value": "CNA description"}
                    ],
                    "affected": [{"product": "Example", "vendor": "Vendor"}],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {"lang": "en", "description": "CWE-79"}
                            ]
                        }
                    ],
                    "references": [{"url": "https://example.invalid/advisory"}],
                }
            },
        }
    )
    assert result is not None
    assert result["state"] == "PUBLISHED"
    assert result["assigner_short_name"] == "Example CNA"
    assert result["description"] == "CNA description"
    assert result["affected"][0]["product"] == "Example"
    assert result["problem_types"][0]["description"] == "CWE-79"


def test_nuclei_metadata_never_claims_weaponization() -> None:
    result = evidence._normalize_nuclei(
        {
            "ID": "CVE-2099-0001",
            "Info": {
                "Name": "Synthetic detection",
                "Severity": "critical",
                "Classification": {"CVSSScore": "9.8"},
            },
            "file_path": "http/cves/2099/CVE-2099-0001.yaml",
        }
    )
    assert result["template_available"] is True
    assert result["evidence_level"] == "detection_template"
    assert result["protocol"] == "http"
    assert "weaponization" in result["scope_note"]
    assert "weaponized_exploit" not in result


@pytest.mark.asyncio
async def test_rejected_cve_program_conflict_lowers_confidence(tmp_path) -> None:
    repo = Repository(tmp_path / "test.db")
    result = await assess_finding_service(
        finding(cve_id="CVE-2099-0003"), repo=repo
    )
    assert result.confidence.value == "low"
    assert any(
        "CVE Program record is REJECTED" in item
        for item in result.source_conflicts
    )
    assert any("does not prove weaponization" in item for item in result.rationale)
