"""Environment-backed configuration for the local-first server."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    mcp_transport: str = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    data_dir: Path = Path(".vulncompass")
    nvd_api_key: str = Field(default="", repr=False)
    nuclei_templates_enabled: bool = True
    nuclei_templates_ref: str = "main"
    request_timeout_seconds: float = Field(default=20.0, ge=1.0, le=60.0)
    cache_ttl_seconds: int = Field(default=86_400, ge=60)


settings = Settings()
