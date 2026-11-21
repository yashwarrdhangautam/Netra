"""Typed, per-profile scan configuration (spec S7).

Only keys on the allow-list for a profile are accepted, each with a fixed type
and range. Free text, nested structures and URLs carrying user names or
passwords are refused so that tokens and cookies cannot be stored in scan
configuration at rest.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from typing import Any

from netra.db.models.scan import ScanProfile

_URL_CREDENTIALS = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")


def _is_int(low: int, high: int) -> Callable[[Any], bool]:
    def check(value: Any) -> bool:
        return type(value) is int and low <= value <= high

    return check


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


RATE_LIMIT = ("rate_limit", "integer 1-100", _is_int(1, 100))
TEST_SQLI = ("test_sqli", "boolean", _is_bool)
ENABLE_NUCLEI = ("enable_nuclei", "boolean", _is_bool)
AGENTIC = ("agentic", "boolean", _is_bool)
PROGRAM_ID = ("program_id", "UUID string", _is_uuid)
# Fast mode: nuclei runs the templates for the technology httpx detected plus a fixed
# baseline, instead of the whole set. Runs are marked tech_targeted in coverage.
TECH_TARGETED = ("tech_targeted", "boolean", _is_bool)
# Test hosts whose root answers 4xx in full instead of the light pass.
FULL_SCAN_4XX = ("full_scan_4xx_hosts", "boolean", _is_bool)

_BOUNTY_KEYS = (RATE_LIMIT, ENABLE_NUCLEI, AGENTIC, PROGRAM_ID)

# Profiles without a dedicated configuration get the general keys only.
_GENERAL_KEYS = (RATE_LIMIT, TEST_SQLI)
_WEB_KEYS = (RATE_LIMIT, TEST_SQLI, TECH_TARGETED, FULL_SCAN_4XX)

PROFILE_KEYS: dict[str, tuple[tuple[str, str, Callable[[Any], bool]], ...]] = {
    ScanProfile.QUICK: _WEB_KEYS,
    ScanProfile.STANDARD: _WEB_KEYS,
    ScanProfile.DEEP: _WEB_KEYS,
    ScanProfile.API_ONLY: _WEB_KEYS,
    ScanProfile.CLOUD: _GENERAL_KEYS,
    ScanProfile.MOBILE: _GENERAL_KEYS,
    ScanProfile.CONTAINER: _GENERAL_KEYS,
    ScanProfile.AI_LLM: _GENERAL_KEYS,
    ScanProfile.CUSTOM: _GENERAL_KEYS,
    ScanProfile.BUGBOUNTY_PASSIVE: _BOUNTY_KEYS,
    ScanProfile.BUGBOUNTY_ACTIVE: _BOUNTY_KEYS,
}


# Profiles with no pipeline behind them yet. Creating one would run the web chain
# against a target it does not describe, so creation is refused with the reason.
DEFERRED_PROFILES = {
    ScanProfile.CLOUD: "cloud assessment is not implemented",
    ScanProfile.AI_LLM: "AI/LLM assessment is not implemented",
    ScanProfile.MOBILE: "mobile assessment is not implemented",
    ScanProfile.CUSTOM: "custom profiles are not configurable yet",
}


def _reject_embedded_credentials(value: Any, key: str) -> None:
    if isinstance(value, str) and _URL_CREDENTIALS.search(value):
        raise ValueError(f"config key '{key}' contains credentials in a URL")


def validate_scan_config(profile: str, config: dict | None) -> dict:
    """Validate and return a clean configuration for ``profile``.

    Raises:
        ValueError: unknown profile, unknown key, wrong type or range, or
            embedded URL credentials.
    """
    try:
        profile_key = ScanProfile(profile)
    except ValueError as exc:
        raise ValueError(f"unknown scan profile '{profile}'") from exc
    if profile_key in DEFERRED_PROFILES:
        raise ValueError(f"profile '{profile}' is not available: {DEFERRED_PROFILES[profile_key]}")

    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError("scan config must be an object")

    allowed = {name: (desc, check) for name, desc, check in PROFILE_KEYS[profile_key]}
    clean: dict[str, Any] = {}
    for key, value in config.items():
        if key not in allowed:
            raise ValueError(f"config key '{key}' is not allowed for profile '{profile}'")
        description, check = allowed[key]
        _reject_embedded_credentials(value, key)
        if not check(value):
            raise ValueError(f"config key '{key}' must be {description}")
        clean[key] = value
    return clean
