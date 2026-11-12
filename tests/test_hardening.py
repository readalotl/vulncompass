"""Tests for live evidence mode, Postgres storage backend, and HTTP auth.

These tests do NOT make real network calls and do NOT require a running
Postgres instance. All external dependencies are monkeypatched.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulncompass import evidence as ev
from vulncompass.models import (
    EvidenceMode,
    EvidenceSnapshot,
    FindingInput,
)
from vulncompass.storage import PostgresRepository, Repository, get_repository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(**kwargs) -> FindingInput:
    defaults = {
        "finding_id": "F-LIVE-001",
        "source_vendor": "test-vendor",
        "source_finding_id": "TV-001",
        "cve_id": "CVE-2099-0001",
        "asset_id": "ASSET-001",
        "applicability": "confirmed_affected",
        "internet_exposure": "public",
        "mission_criticality": "high",
        "compensating_controls": "absent",
    }
    defaults.update(kwargs)
    return FindingInput.model_validate(defaults)


def _ts() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# Live evidence mode — _load_live
# ===========================================================================


@pytest.mark.asyncio
async def test_live_mode_fetches_all_five_sources(monkeypatch, tmp_path):
    """_load_live must attempt all five public sources and build a snapshot."""
    calls: list[str] = []

    async def fake_json(base_url, path, **kwargs):
        calls.append(base_url)
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.NVD_BASE:
            return {"vulnerabilities": []}
        if base_url == ev.CISA_FEED_BASE:
            return {"catalogVersion": "test", "vulnerabilities": []}
        # vulnrichment
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        calls.append(base_url)
        return (
            '{"ID":"CVE-2099-0001","Info":{"Name":"Syn","Severity":"high",'
            '"Classification":{}},"file_path":"http/cves/2099/CVE-2099-0001.yaml"}\n'
        )

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)

    snap = await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    assert snap.mode is EvidenceMode.LIVE
    assert snap.cve_id == "CVE-2099-0001"
    # All five base URLs must have been called.
    assert ev.MITRE_CVE_BASE in calls
    assert ev.NVD_BASE in calls
    assert ev.CISA_FEED_BASE in calls
    assert ev.VULNRICHMENT_BASE in calls
    assert ev.NUCLEI_TEMPLATES_BASE in calls


@pytest.mark.asyncio
async def test_live_mode_writes_cache_file(monkeypatch, tmp_path):
    """After a live fetch the snapshot is serialised to the cache directory."""

    async def fake_json(base_url, path, **kwargs):
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.NVD_BASE:
            return {"vulnerabilities": []}
        if base_url == ev.CISA_FEED_BASE:
            return {"catalogVersion": "v1", "vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        return ""  # empty nuclei index

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)

    await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    cache_file = tmp_path / "cache" / "CVE-2099-0001.json"
    assert cache_file.exists(), "Cache file must be written after a live fetch"
    snap = EvidenceSnapshot.model_validate_json(cache_file.read_text())
    assert snap.cve_id == "CVE-2099-0001"


@pytest.mark.asyncio
async def test_live_mode_partial_failure_returns_snapshot(monkeypatch, tmp_path):
    """If some sources are unavailable the snapshot is still returned with
    those sources listed in ``unavailable_sources``."""
    from vulncompass.utils import UpstreamServiceError

    async def fake_json(base_url, path, **kwargs):
        if base_url == ev.MITRE_CVE_BASE:
            raise UpstreamServiceError("CVE API down")
        if base_url == ev.NVD_BASE:
            return {"vulnerabilities": []}
        if base_url == ev.CISA_FEED_BASE:
            return {"catalogVersion": "v1", "vulnerabilities": []}
        raise UpstreamServiceError("vulnrichment down")

    async def fake_text(base_url, path, **kwargs):
        raise UpstreamServiceError("nuclei down")

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)

    snap = await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    assert "cve_program" in snap.unavailable_sources
    assert "cisa_vulnrichment" in snap.unavailable_sources
    assert "nuclei_templates" in snap.unavailable_sources
    # NVD and KEV succeeded — they must NOT be in unavailable_sources.
    assert "nvd" not in snap.unavailable_sources
    assert "cisa_kev" not in snap.unavailable_sources


@pytest.mark.asyncio
async def test_live_mode_caches_kev_catalog(monkeypatch, tmp_path):
    """The KEV catalog is fetched once and reused for subsequent calls within TTL."""
    fetch_count = 0

    async def fake_json(base_url, path, **kwargs):
        nonlocal fetch_count
        if base_url == ev.CISA_FEED_BASE:
            fetch_count += 1
            return {"catalogVersion": "v1", "vulnerabilities": []}
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.NVD_BASE:
            return {"vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        return ""

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)

    await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)
    await ev.get_evidence("CVE-2099-0002", EvidenceMode.LIVE)

    assert fetch_count == 1, (
        "KEV catalog must be fetched only once per TTL window, not once per CVE"
    )


@pytest.mark.asyncio
async def test_live_mode_kev_listed_detected(monkeypatch, tmp_path):
    """When the CVE appears in the KEV catalog, kev.listed must be True."""

    async def fake_json(base_url, path, **kwargs):
        if base_url == ev.CISA_FEED_BASE:
            return {
                "catalogVersion": "v1",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2099-0001",
                        "dateAdded": "2099-01-05",
                        "dueDate": "2099-01-26",
                        "requiredAction": "Apply mitigations.",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ],
            }
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.NVD_BASE:
            return {"vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        return ""

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)

    snap = await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    assert snap.kev is not None
    assert snap.kev["listed"] is True
    assert snap.kev["date_added"] == "2099-01-05"


@pytest.mark.asyncio
async def test_live_mode_nvd_api_key_sent_in_header(monkeypatch, tmp_path):
    """When nvd_api_key is set it must be forwarded as a header to NVD."""
    captured_headers: list[dict] = []

    async def fake_json(base_url, path, **kwargs):
        if base_url == ev.NVD_BASE:
            captured_headers.append(kwargs.get("headers") or {})
            return {"vulnerabilities": []}
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.CISA_FEED_BASE:
            return {"catalogVersion": "v1", "vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        return ""

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)
    monkeypatch.setattr(ev.settings, "nvd_api_key", "test-nvd-key-123")

    await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    assert captured_headers, "NVD must have been called"
    assert captured_headers[0].get("apiKey") == "test-nvd-key-123", (
        "NVD API key must be forwarded as apiKey header"
    )


@pytest.mark.asyncio
async def test_live_mode_no_nvd_key_sends_no_header(monkeypatch, tmp_path):
    """Without an NVD key no Authorization/apiKey header must be sent."""
    captured_headers: list = []

    async def fake_json(base_url, path, **kwargs):
        if base_url == ev.NVD_BASE:
            captured_headers.append(kwargs.get("headers"))
            return {"vulnerabilities": []}
        if base_url == ev.MITRE_CVE_BASE:
            return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        if base_url == ev.CISA_FEED_BASE:
            return {"catalogVersion": "v1", "vulnerabilities": []}
        return {"containers": {"adp": []}}

    async def fake_text(base_url, path, **kwargs):
        return ""

    monkeypatch.setattr(ev, "fetch_public_json", fake_json)
    monkeypatch.setattr(ev, "fetch_public_text", fake_text)
    monkeypatch.setattr(ev, "_kev_catalog_cache", None)
    monkeypatch.setattr(ev, "_nuclei_catalog_cache", None)
    monkeypatch.setattr(ev.settings, "data_dir", tmp_path)
    monkeypatch.setattr(ev.settings, "nvd_api_key", "")

    await ev.get_evidence("CVE-2099-0001", EvidenceMode.LIVE)

    assert captured_headers and captured_headers[0] is None, (
        "No header dict must be passed to NVD when nvd_api_key is empty"
    )


# ===========================================================================
# Storage factory — get_repository()
# ===========================================================================


def test_get_repository_returns_sqlite_by_default():
    """Without DATABASE_URL get_repository() must return a SQLite Repository."""
    repo = get_repository(database_url="")
    assert isinstance(repo, Repository)


def test_get_repository_returns_postgres_when_url_set():
    """With a DATABASE_URL get_repository() must return a PostgresRepository."""
    repo = get_repository(database_url="postgresql://user:pass@localhost/db")
    assert isinstance(repo, PostgresRepository)
    assert repo._url == "postgresql://user:pass@localhost/db"


def test_postgres_repository_raises_on_missing_psycopg2():
    """PostgresRepository._connect() must raise RuntimeError with install hint
    when psycopg2 is not available (which is the case in this test env)."""
    repo = PostgresRepository("postgresql://user:pass@localhost/db")
    with pytest.raises(RuntimeError, match="psycopg2-binary"):
        repo._connect()


def test_sqlite_repository_round_trip(tmp_path):
    """SQLite Repository must persist and retrieve an assessment."""
    from datetime import datetime, timezone

    from vulncompass.models import (
        Assessment,
        Confidence,
        EvidenceMode,
        EvidenceSnapshot,
        Recommendation,
        ReviewStatus,
    )

    repo = Repository(tmp_path / "test.db")
    finding = FindingInput.model_validate(
        {
            "finding_id": "F-STORE-001",
            "source_vendor": "tv",
            "source_finding_id": "tv-1",
            "cve_id": "CVE-2099-0001",
            "asset_id": "A-001",
        }
    )
    snap = EvidenceSnapshot(
        cve_id="CVE-2099-0001",
        mode=EvidenceMode.FIXTURE,
        retrieved_at=datetime.now(timezone.utc),
    )
    assessment = Assessment(
        finding_id="F-STORE-001",
        cve_id="CVE-2099-0001",
        vendor_recommendation={},
        vulncompass_recommendation=Recommendation.IMMEDIATE_REVIEW,
        agreement=None,
        comparison_explanation="test",
        confidence=Confidence.HIGH,
        policy_rules=["K-1"],
        rationale=["test rationale"],
        missing_information=[],
        source_conflicts=[],
        evidence=snap,
        policy_version="test",
        review_status=ReviewStatus.PENDING_REVIEW,
        assessed_at=datetime.now(timezone.utc),
    )
    repo.save_assessment(finding, assessment)
    result = repo.get_assessment("F-STORE-001")
    assert result is not None
    loaded_finding, loaded_assessment = result
    assert loaded_finding.finding_id == "F-STORE-001"
    assert (
        loaded_assessment.vulncompass_recommendation is Recommendation.IMMEDIATE_REVIEW
    )


def test_sqlite_latest_snapshot(tmp_path):
    """latest_snapshot must return None when no snapshot exists."""
    repo = Repository(tmp_path / "test.db")
    assert repo.latest_snapshot("F-NONEXISTENT") is None


# ===========================================================================
# HTTP auth middleware
# ===========================================================================


def test_auth_middleware_rejects_missing_token():
    """A request without Authorization must receive 401."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from vulncompass.app import _make_auth_middleware

    async def homepage(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(_make_auth_middleware("secret-key"))
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/")
    assert resp.status_code == 401
    assert resp.json()["error"] == "Unauthorized"


def test_auth_middleware_rejects_wrong_token():
    """A request with a wrong token must receive 401."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from vulncompass.app import _make_auth_middleware

    async def homepage(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(_make_auth_middleware("correct-key"))
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/", headers={"Authorization": "Bearer wrong-key"})
    assert resp.status_code == 401


def test_auth_middleware_accepts_correct_token():
    """A request with the correct Bearer token must pass through."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from vulncompass.app import _make_auth_middleware

    async def homepage(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(_make_auth_middleware("my-secret"))
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/", headers={"Authorization": "Bearer my-secret"})
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_auth_middleware_no_key_no_class():
    """_make_auth_middleware must be callable even without starlette in scope.
    Smoke-test: calling _make_auth_middleware('x') returns a class."""
    from vulncompass.app import _make_auth_middleware

    cls = _make_auth_middleware("x")
    assert callable(cls)
