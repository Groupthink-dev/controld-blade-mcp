"""Configuration, write gates, and exception hierarchy."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0
RETRY_MAX_DELAY = 30.0
_MAX_TEXT_LEN = 200


# ── Exceptions ──────────────────────────────────────────────────────


class ControlDError(Exception):
    """Base exception for Control-D API errors."""

    def __init__(self, message: str, details: str = "") -> None:
        super().__init__(message)
        self.details = details


class AuthError(ControlDError):
    """Authentication failed — invalid or expired API key."""


class NotFoundError(ControlDError):
    """Requested resource does not exist."""


class RateLimitError(ControlDError):
    """Rate limit exceeded."""


class ControlDConnectionError(ControlDError):
    """Cannot connect to Control-D API."""


# ── Config ──────────────────────────────────────────────────────────


@dataclass
class Config:
    """Parsed environment configuration."""

    api_key: str
    write_enabled: bool


def resolve_config() -> Config:
    """Parse configuration from environment variables."""
    api_key = os.environ.get("CONTROLD_API_KEY", "").strip()
    if not api_key:
        raise ValueError("CONTROLD_API_KEY environment variable is required")
    write_enabled = os.environ.get("CONTROLD_WRITE_ENABLED", "").lower() == "true"
    return Config(api_key=api_key, write_enabled=write_enabled)


# ── Write gates ─────────────────────────────────────────────────────


def is_write_enabled() -> bool:
    """Check if write operations are enabled."""
    return os.environ.get("CONTROLD_WRITE_ENABLED", "").lower() == "true"


def require_write() -> str | None:
    """Return error message if writes are disabled, else None."""
    if not is_write_enabled():
        return "Error: Write operations are disabled. Set CONTROLD_WRITE_ENABLED=true to enable."
    return None


def require_confirm(confirm: bool, action: str) -> str | None:
    """Return error message if confirm is not set, else None."""
    if not confirm:
        return (
            f"Error: {action} requires explicit confirmation. "
            "Set confirm=true to proceed. This is a safety gate — "
            "this action cannot be undone."
        )
    return None
