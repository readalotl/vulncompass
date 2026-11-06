"""Public evidence adapters with fixture, cache, and live modes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulncompass.config import settings
from vulncompass.models import EvidenceMode, EvidenceSnapshot, Provenance
from vulncompass.utils import UpstreamServiceError, fetch_public_json

NVD_BASE = "https://services.nvd.nist.gov/rest/json/"
CISA_FEED_BASE = "https://www.cisa.gov/sites/default/files/feeds/"
VULNRICHMENT_BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/"
_kev_catalog_cache: tuple[datetime, dict[str, Any]] | None = None


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
            "nvd": {"status": "UNKNOWN", "description": "No fixture record."},
            "kev": None,
            "vulnrichment": None,
            "unavailable_sources": ["fixture"],
        }
    return EvidenceSnapshot(
        cve_id=cve_id,
        mode=EvidenceMode.FIXTURE,
        nvd=record.get("nvd"),
        kev=record.get("kev"),
        vulnrichment=record.get("vulnrichment"),
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

    nvd = kev = vulnrichment = None
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

    snapshot = EvidenceSnapshot(
        cve_id=cve_id,
        mode=EvidenceMode.LIVE,
        retrieved_at=retrieved_at,
        nvd=nvd,
        kev=kev,
        vulnrichment=vulnrichment,
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
