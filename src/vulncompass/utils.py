"""Bounded outbound HTTP helpers for approved public vulnerability sources."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

MAX_RESPONSE_BYTES = 8_000_000
APPROVED_ORIGINS = {
    "https://cveawg.mitre.org/api/",
    "https://services.nvd.nist.gov/rest/json/",
    "https://www.cisa.gov/sites/default/files/feeds/",
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/",
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/",
}


class UpstreamServiceError(RuntimeError):
    """Sanitized external-service failure safe to expose to a client."""


def _validate_relative_path(path: str) -> str:
    parsed = urlsplit(path)
    decoded_path = parsed.path
    for _ in range(3):
        decoded = unquote(decoded_path)
        if decoded == decoded_path:
            break
        decoded_path = decoded
    segments = decoded_path.replace("\\", "/").split("/")
    if (
        not path
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or decoded_path.startswith(("/", "\\"))
        or any(segment in {".", ".."} for segment in segments)
    ):
        raise ValueError(
            "path must be relative and may not contain a query or fragment"
        )
    return path


async def _fetch_public_bytes(
    base_url: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> bytes:
    """Fetch bounded content from an exact operator-controlled origin.

    Only public CVE identifiers and public API parameters belong in ``params``.
    Organizational finding and asset fields must never be passed here.
    """
    if base_url not in APPROVED_ORIGINS:
        raise ValueError("base_url is not an approved public evidence origin")
    safe_path = _validate_relative_path(path)
    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,
        ) as client:
            async with client.stream(
                "GET", safe_path, params=params, headers=headers
            ) as response:
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise UpstreamServiceError(
                            "Upstream response exceeded the size limit."
                        )
                return bytes(content)
    except UpstreamServiceError:
        raise
    except httpx.HTTPStatusError as exc:
        raise UpstreamServiceError(
            f"Upstream service returned status {exc.response.status_code}."
        ) from None
    except httpx.RequestError:
        raise UpstreamServiceError("Upstream service request failed.") from None


async def fetch_public_json(
    base_url: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> Any:
    """Fetch JSON from an exact operator-controlled public evidence origin."""
    content = await _fetch_public_bytes(
        base_url,
        path,
        params=params,
        headers=headers,
        timeout=timeout,
    )
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise UpstreamServiceError("Upstream service returned invalid JSON.") from None


async def fetch_public_text(
    base_url: str,
    path: str,
    *,
    timeout: float = 20.0,
) -> str:
    """Fetch UTF-8 text from an exact public origin for bounded indexes."""
    content = await _fetch_public_bytes(base_url, path, timeout=timeout)
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        raise UpstreamServiceError("Upstream service returned invalid text.") from None
