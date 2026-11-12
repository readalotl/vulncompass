"""Public evidence adapters with fixture, cache, and live modes."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulncompass.config import settings
from vulncompass.models import EvidenceMode, EvidenceSnapshot, Provenance
from vulncompass.utils import (
    UpstreamServiceError,
    fetch_public_json,
    fetch_public_text,
)

MITRE_CVE_BASE = "https://cveawg.mitre.org/api/"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/"
CISA_FEED_BASE = "https://www.cisa.gov/sites/default/files/feeds/"
VULNRICHMENT_BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/"
NUCLEI_TEMPLATES_BASE = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/"
)
_kev_catalog_cache: tuple[datetime, dict[str, Any]] | None = None
_nuclei_catalog_cache: tuple[datetime, dict[str, dict[str, Any]]] | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fixture_path() -> Path:
    return Path(__file__).with_name("data") / "fixtures.json"


def _cache_path(cve_id: str) -> Path:
    safe_name = cve_id.replace("/", "_")
    return settings.data_dir / "cache" / f"{safe_name}.json"


def _load_fixture(cve_id: str) -> EvidenceSnapshot:
    payload = json.loads(_fixture_path().read_text(encoding="utf-8"))
    record = payload.get(cve_id)
    if record is None:
        record = {
            "cve_program": {
                "state": "UNKNOWN",
                "description": "No fixture record.",
            },
            "nvd": {"status": "UNKNOWN", "description": "No fixture record."},
            "kev": None,
            "vulnrichment": None,
            "nuclei": {
                "template_available": False,
                "evidence_level": "none",
            },
            "unavailable_sources": ["fixture"],
        }
    return EvidenceSnapshot(
        cve_id=cve_id,
        mode=EvidenceMode.FIXTURE,
        cve_program=record.get("cve_program"),
        nvd=record.get("nvd"),
        kev=record.get("kev"),
        vulnrichment=record.get("vulnrichment"),
        nuclei=record.get("nuclei"),
        unavailable_sources=record.get("unavailable_sources", []),
        provenance=[
            Provenance(
                source="VulnCompass fixture",
                record_url=f"vulncompass://fixture/{cve_id}",
                retrieved_at=_now(),
            )
        ],
    )


def _load_cached(cve_id: str) -> EvidenceSnapshot:
    path = _cache_path(cve_id)
    if not path.exists():
        raise ValueError(
            f"No cached evidence exists for {cve_id}; run live mode once "
            "or use fixture mode."
        )
    snapshot = EvidenceSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
    return snapshot.model_copy(update={"mode": EvidenceMode.CACHED})


def _save_cache(snapshot: EvidenceSnapshot) -> None:
    path = _cache_path(snapshot.cve_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")


def _normalize_nvd(payload: dict[str, Any]) -> dict[str, Any] | None:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    metrics = cve.get("metrics", {})
    metric = next(
        iter(
            metrics.get("cvssMetricV40", [])
            or metrics.get("cvssMetricV31", [])
            or metrics.get("cvssMetricV30", [])
            or metrics.get("cvssMetricV2", [])
        ),
        {},
    )
    cvss = metric.get("cvssData", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value") for item in descriptions if item.get("lang") == "en"),
        None,
    )
    configurations = cve.get("configurations", [])
    return {
        "status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": description,
        "cvss": {
            "version": cvss.get("version"),
            "base_score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity") or metric.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "source": metric.get("source"),
        },
        "weaknesses": cve.get("weaknesses", []),
        "configurations": configurations,
        "references": cve.get("references", []),
    }


def _english_value(items: list[dict[str, Any]]) -> str | None:
    return next(
        (item.get("value") for item in items if item.get("lang") == "en"),
        next((item.get("value") for item in items), None),
    )


def _normalize_cve_program(payload: dict[str, Any]) -> dict[str, Any] | None:
    metadata = payload.get("cveMetadata") or {}
    cna = (payload.get("containers") or {}).get("cna") or {}
    if not metadata and not cna:
        return None
    problem_types = []
    for group in cna.get("problemTypes") or []:
        problem_types.extend(group.get("descriptions") or [])
    rejected_reasons = cna.get("rejectedReasons") or []
    return {
        "state": metadata.get("state"),
        "assigner_org_id": metadata.get("assignerOrgId"),
        "assigner_short_name": metadata.get("assignerShortName"),
        "date_published": metadata.get("datePublished"),
        "date_updated": metadata.get("dateUpdated"),
        "description": _english_value(cna.get("descriptions") or []),
        "rejected_reason": _english_value(rejected_reasons),
        "affected": cna.get("affected") or [],
        "problem_types": problem_types,
        "metrics": cna.get("metrics") or [],
        "references": cna.get("references") or [],
        "provider": cna.get("providerMetadata"),
    }


def _nuclei_index_path() -> str:
    ref = settings.nuclei_templates_ref
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", ref) or ".." in ref.split("/"):
        raise ValueError("nuclei_templates_ref contains unsupported characters")
    return f"{ref}/cves.json"


async def _get_nuclei_catalog() -> dict[str, dict[str, Any]]:
    global _nuclei_catalog_cache
    now = _now()
    if _nuclei_catalog_cache is not None:
        cached_at, catalog = _nuclei_catalog_cache
        if (now - cached_at).total_seconds() < settings.cache_ttl_seconds:
            return catalog
    text = await fetch_public_text(
        NUCLEI_TEMPLATES_BASE,
        _nuclei_index_path(),
        timeout=settings.request_timeout_seconds,
    )
    catalog: dict[str, dict[str, Any]] = {}
    try:
        for line in text.splitlines():
            if line.strip():
                record = json.loads(line)
                cve_id = record.get("ID")
                if isinstance(cve_id, str):
                    catalog[cve_id.upper()] = record
    except (json.JSONDecodeError, AttributeError, TypeError):
        raise UpstreamServiceError(
            "Nuclei template index returned invalid data."
        ) from None
    _nuclei_catalog_cache = (now, catalog)
    return catalog


def _normalize_nuclei(
    record: dict[str, Any] | None,
) -> dict[str, Any]:
    if record is None:
        return {
            "template_available": False,
            "evidence_level": "none",
            "scope_note": (
                "No template in the index does not establish that no exploit exists."
            ),
        }
    info = record.get("Info") or {}
    classification = info.get("Classification") or {}
    template_path = record.get("file_path")
    protocol = (
        template_path.split("/", 1)[0]
        if isinstance(template_path, str) and "/" in template_path
        else None
    )
    return {
        "template_available": True,
        "template_id": record.get("ID"),
        "name": info.get("Name"),
        "severity": info.get("Severity"),
        "description": info.get("Description"),
        "cvss_score": classification.get("CVSSScore"),
        "protocol": protocol,
        "template_path": template_path,
        "repository_ref": settings.nuclei_templates_ref,
        "evidence_level": "detection_template",
        "scope_note": (
            "Template availability is community supporting evidence and does not "
            "prove weaponization, exploitation in the wild, or local applicability."
        ),
    }


def _normalize_kev(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    for record in payload.get("vulnerabilities", []):
        if record.get("cveID") == cve_id:
            return {
                "listed": True,
                "date_added": record.get("dateAdded"),
                "due_date": record.get("dueDate"),
                "required_action": record.get("requiredAction"),
                "known_ransomware_campaign_use": record.get(
                    "knownRansomwareCampaignUse"
                ),
                "vendor_project": record.get("vendorProject"),
                "product": record.get("product"),
                "vulnerability_name": record.get("vulnerabilityName"),
                "notes": record.get("notes"),
                "catalog_version": payload.get("catalogVersion"),
                "catalog_date_released": payload.get("dateReleased"),
            }
    return {"listed": False, "catalog_version": payload.get("catalogVersion")}


async def _get_kev_catalog() -> dict[str, Any]:
    global _kev_catalog_cache
    now = _now()
    if _kev_catalog_cache is not None:
        cached_at, payload = _kev_catalog_cache
        if (now - cached_at).total_seconds() < settings.cache_ttl_seconds:
            return payload
    payload = await fetch_public_json(
        CISA_FEED_BASE,
        "known_exploited_vulnerabilities.json",
        timeout=settings.request_timeout_seconds,
    )
    _kev_catalog_cache = (now, payload)
    return payload


def _vulnrichment_path(cve_id: str) -> str:
    _, year, serial_text = cve_id.split("-")
    bucket = f"{int(serial_text) // 1000}xxx"
    return f"{year}/{bucket}/{cve_id}.json"


def _normalize_vulnrichment(payload: dict[str, Any]) -> dict[str, Any] | None:
    adp = payload.get("containers", {}).get("adp", [])
    cisa = next(
        (
            item
            for item in adp
            if item.get("providerMetadata", {}).get("shortName") == "CISA-ADP"
            or item.get("title") == "CISA ADP Vulnrichment"
        ),
        None,
    )
    if not cisa:
        return None
    ssvc = None
    kev = None
    for metric in cisa.get("metrics", []):
        other = metric.get("other", {})
        if other.get("type") == "ssvc":
            ssvc = other.get("content")
        if other.get("type") == "kev":
            kev = other.get("content")
    return {
        "ssvc": ssvc,
        "kev": kev,
        "provider": cisa.get("providerMetadata"),
    }


async def _load_live(cve_id: str) -> EvidenceSnapshot:
    retrieved_at = _now()
    unavailable: list[str] = []
    provenance: list[Provenance] = []
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else None

    cve_program = nvd = kev = vulnrichment = nuclei = None
    try:
        raw = await fetch_public_json(
            MITRE_CVE_BASE,
            f"cve/{cve_id}",
            timeout=settings.request_timeout_seconds,
        )
        cve_program = _normalize_cve_program(raw)
        provenance.append(
            Provenance(
                source="CVE Program CVE Services",
                record_url=f"https://www.cve.org/CVERecord?id={cve_id}",
                retrieved_at=retrieved_at,
            )
        )
    except UpstreamServiceError:
        unavailable.append("cve_program")

    try:
        raw = await fetch_public_json(
            NVD_BASE,
            "cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=settings.request_timeout_seconds,
        )
        nvd = _normalize_nvd(raw)
        provenance.append(
            Provenance(
                source="NIST NVD CVE API 2.0",
                record_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                retrieved_at=retrieved_at,
            )
        )
    except UpstreamServiceError:
        unavailable.append("nvd")

    try:
        raw = await _get_kev_catalog()
        kev = _normalize_kev(raw, cve_id)
        provenance.append(
            Provenance(
                source="CISA Known Exploited Vulnerabilities Catalog",
                record_url=(
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    f"?field_cve={cve_id}"
                ),
                retrieved_at=retrieved_at,
            )
        )
    except UpstreamServiceError:
        unavailable.append("cisa_kev")

    try:
        path = _vulnrichment_path(cve_id)
        raw = await fetch_public_json(
            VULNRICHMENT_BASE,
            path,
            timeout=settings.request_timeout_seconds,
        )
        vulnrichment = _normalize_vulnrichment(raw)
        provenance.append(
            Provenance(
                source="CISA ADP Vulnrichment",
                record_url=f"{VULNRICHMENT_BASE}{path}",
                retrieved_at=retrieved_at,
            )
        )
    except UpstreamServiceError:
        unavailable.append("cisa_vulnrichment")

    if settings.nuclei_templates_enabled:
        try:
            catalog = await _get_nuclei_catalog()
            nuclei = _normalize_nuclei(catalog.get(cve_id))
            provenance.append(
                Provenance(
                    source="ProjectDiscovery Nuclei Templates index",
                    record_url=(f"{NUCLEI_TEMPLATES_BASE}{_nuclei_index_path()}"),
                    retrieved_at=retrieved_at,
                )
            )
        except UpstreamServiceError:
            unavailable.append("nuclei_templates")

    snapshot = EvidenceSnapshot(
        cve_id=cve_id,
        mode=EvidenceMode.LIVE,
        retrieved_at=retrieved_at,
        cve_program=cve_program,
        nvd=nvd,
        kev=kev,
        vulnrichment=vulnrichment,
        nuclei=nuclei,
        unavailable_sources=unavailable,
        provenance=provenance,
    )
    _save_cache(snapshot)
    return snapshot


async def get_evidence(cve_id: str, mode: EvidenceMode) -> EvidenceSnapshot:
    if mode is EvidenceMode.FIXTURE:
        return _load_fixture(cve_id)
    if mode is EvidenceMode.CACHED:
        return _load_cached(cve_id)
    return await _load_live(cve_id)
