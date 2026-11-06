"""Regression tests for the outbound public-evidence boundary."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from vulncompass import utils


@pytest.mark.parametrize(
    "path",
    [
        "http://169.254.169.254/latest/meta-data",
        "https://localhost/admin",
        "//127.0.0.1/admin",
        "/absolute/path",
        "../admin",
        "datasets/../../admin",
        "%2e%2e/admin",
        "%252e%252e/admin",
        "datasets?target=http://127.0.0.1",
        "datasets#fragment",
        "\\\\127.0.0.1\\admin",
        "",
    ],
)
def test_validate_relative_path_rejects_destination_override(path: str) -> None:
    with pytest.raises(ValueError, match="path must be relative"):
        utils._validate_relative_path(path)


def test_only_exact_origins_are_approved() -> None:
    assert all(origin.startswith("https://") for origin in utils.APPROVED_ORIGINS)
    assert "https://evil.example/" not in utils.APPROVED_ORIGINS


class _FakeClient:
    init_kwargs: dict[str, Any] = {}
    response = httpx.Response(200, json={"results": []})

    def __init__(self, **kwargs: Any) -> None:
        type(self).init_kwargs = kwargs

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    class _Stream:
        def __init__(self, response: httpx.Response) -> None:
            self.response = response

        async def __aenter__(self) -> httpx.Response:
            return self.response

        async def __aexit__(self, *args: object) -> None:
            return None

    def stream(self, method: str, path: str, **kwargs: Any) -> _Stream:
        self.response.request = httpx.Request(
            method, f"https://services.nvd.nist.gov/rest/json/{path}"
        )
        return self._Stream(self.response)


@pytest.mark.asyncio
async def test_fetch_uses_fixed_origin_and_safe_client_policy(monkeypatch) -> None:
    monkeypatch.setattr(utils.httpx, "AsyncClient", _FakeClient)
    origin = "https://services.nvd.nist.gov/rest/json/"
    result = await utils.fetch_public_json(
        origin, "cves/2.0", params={"cveId": "CVE-2099-0001"}
    )
    assert result == {"results": []}
    assert _FakeClient.init_kwargs["base_url"] == origin
    assert _FakeClient.init_kwargs["follow_redirects"] is False
    assert _FakeClient.init_kwargs["trust_env"] is False


@pytest.mark.asyncio
async def test_rejected_origin_never_creates_client(monkeypatch) -> None:
    class UnexpectedClient:
        def __init__(self, **kwargs: Any) -> None:
            raise AssertionError("client must not be created")

    monkeypatch.setattr(utils.httpx, "AsyncClient", UnexpectedClient)
    with pytest.raises(ValueError, match="approved public evidence origin"):
        await utils.fetch_public_json("https://evil.example/", "data")


@pytest.mark.asyncio
async def test_upstream_error_is_sanitized(monkeypatch, caplog) -> None:
    sensitive = "SSN 123-45-6789 DOB 1940-01-01 token=secret"
    _FakeClient.response = httpx.Response(500, text=sensitive)
    monkeypatch.setattr(utils.httpx, "AsyncClient", _FakeClient)
    with pytest.raises(utils.UpstreamServiceError) as captured:
        await utils.fetch_public_json(
            "https://services.nvd.nist.gov/rest/json/", "cves/2.0"
        )
    assert str(captured.value) == "Upstream service returned status 500."
    assert sensitive not in str(captured.value)
    assert sensitive not in caplog.text

