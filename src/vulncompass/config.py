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

    # Optional Postgres connection URL.
    # When set, VulnCompass uses Postgres instead of the local SQLite file.
    # Example: postgresql://analyst:secret@localhost:5432/vulncompass
    # Leave unset (default) to keep using SQLite — safe for single-analyst use.
    database_url: str = Field(default="", repr=False)

    # MCP HTTP transport API key.
    # Required when mcp_transport="streamable-http".
    # Clients must send:  Authorization: Bearer <mcp_api_key>
    # Leave unset to disable auth (only appropriate for stdio/local use).
    mcp_api_key: str = Field(default="", repr=False)

    nvd_api_key: str = Field(default="", repr=False)
    nuclei_templates_enabled: bool = True
    nuclei_templates_ref: str = "main"
    request_timeout_seconds: float = Field(default=20.0, ge=1.0, le=60.0)
    cache_ttl_seconds: int = Field(default=86_400, ge=60)


settings = Settings()
