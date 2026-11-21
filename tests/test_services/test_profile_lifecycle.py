"""Profiles run only declared phases and deferred profiles are refused (spec 6.3)."""

import pytest

from netra.scanner.profiles import PROFILES
from netra.schemas.scan_config import validate_scan_config
from netra.worker import tasks


def test_chain_is_built_from_declared_phase_list():
    pipeline = tasks.create_scan_pipeline("00000000-0000-0000-0000-000000000001")
    assert [step.task for step in pipeline.tasks] == [
        f"netra.{name}" for name in tasks.WEB_PIPELINE_PHASES
    ]


@pytest.mark.parametrize("profile", ["cloud", "ai_llm", "mobile", "custom"])
def test_deferred_profiles_are_refused_with_reason(profile):
    with pytest.raises(ValueError, match="not available"):
        validate_scan_config(profile, None)


@pytest.mark.parametrize(
    "profile", ["quick", "standard", "deep", "api_only", "bugbounty_passive", "bugbounty_active"]
)
def test_supported_profiles_are_still_accepted(profile):
    assert validate_scan_config(profile, None) == {}


def test_deep_profile_no_longer_declares_code_flags():
    assert not {"run_sast", "run_secrets", "run_dependencies"} & set(PROFILES["deep"])
