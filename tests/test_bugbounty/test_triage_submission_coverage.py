"""Coverage tests for triage severity, submission state machine, and payout estimator."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from netra.bugbounty.submission.payout import SEVERITY_WEIGHTS, PayoutEstimate, estimate_payout
from netra.bugbounty.submission.tracker import InvalidTransition, can_transition, transition
from netra.bugbounty.triage.severity import (
    Severity,
    cap_severity,
    cvss_to_severity,
)
from netra.db.models.bb_submission import SUBMISSION_TRANSITIONS, SubmissionStatus

S = SubmissionStatus


# ---------------------------------------------------------------------------
# triage/severity.py
# ---------------------------------------------------------------------------


def test_severity_from_string_is_case_insensitive() -> None:
    assert Severity.from_string("High") is Severity.HIGH
    assert Severity.from_string("CRITICAL") is Severity.CRITICAL


def test_severity_from_string_rejects_unknown_value() -> None:
    # Current behaviour: unknown labels surface as a bare KeyError.
    with pytest.raises(KeyError):
        Severity.from_string("severe")


def test_severity_to_string_is_lowercase_name() -> None:
    assert Severity.MEDIUM.to_string() == "medium"


def test_severity_ordering_matches_numeric_values() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_cap_severity_without_cap_returns_suggestion() -> None:
    assert cap_severity("critical", None) == "critical"


def test_cap_severity_lowers_to_cap() -> None:
    assert cap_severity("critical", "high") == "high"


def test_cap_severity_keeps_lower_suggestion_when_cap_is_higher() -> None:
    assert cap_severity("low", "critical") == "low"


def test_cap_severity_equal_values() -> None:
    assert cap_severity("medium", "medium") == "medium"


def test_cap_severity_invalid_cap_raises() -> None:
    with pytest.raises(KeyError):
        cap_severity("high", "bogus")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "info"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_cvss_bucket_boundaries(score: float, expected: str) -> None:
    assert cvss_to_severity(score) == expected


def test_cvss_negative_score_falls_through_to_info() -> None:
    # Current behaviour: anything not > 0.0 is reported as info, including invalid negatives.
    assert cvss_to_severity(-1.0) == "info"


# ---------------------------------------------------------------------------
# submission/tracker.py
# ---------------------------------------------------------------------------


def _submission(status: SubmissionStatus) -> SimpleNamespace:
    return SimpleNamespace(
        id="sub-1",
        status=status,
        submitted_at=None,
        verdict_at=None,
        verdict_notes=None,
    )


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (S.DRAFT, S.READY_TO_SEND),
        (S.DRAFT, S.RESOLVED_NA),
        (S.READY_TO_SEND, S.SENT),
        (S.READY_TO_SEND, S.DRAFT),
        (S.SENT, S.ACKNOWLEDGED),
        (S.SENT, S.RESOLVED_NA),
        (S.ACKNOWLEDGED, S.TRIAGING),
        (S.ACKNOWLEDGED, S.RESOLVED_NA),
        (S.TRIAGING, S.RESOLVED_PAID),
        (S.TRIAGING, S.RESOLVED_DUP),
        (S.TRIAGING, S.RESOLVED_NA),
        (S.TRIAGING, S.RESOLVED_INFORMATIVE),
    ],
)
def test_valid_transitions_are_allowed(src: SubmissionStatus, dst: SubmissionStatus) -> None:
    assert can_transition(src, dst) is True


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (S.DRAFT, S.SENT),  # must go through ready_to_send
        (S.DRAFT, S.DRAFT),  # no self-loop
        (S.SENT, S.TRIAGING),  # must be acknowledged first
        (S.ACKNOWLEDGED, S.RESOLVED_PAID),  # must triage first
        (S.READY_TO_SEND, S.RESOLVED_PAID),
    ],
)
def test_invalid_transitions_are_rejected(src: SubmissionStatus, dst: SubmissionStatus) -> None:
    assert can_transition(src, dst) is False


@pytest.mark.parametrize(
    "terminal",
    [S.RESOLVED_PAID, S.RESOLVED_DUP, S.RESOLVED_NA, S.RESOLVED_INFORMATIVE],
)
def test_terminal_states_allow_no_transitions(terminal: SubmissionStatus) -> None:
    assert SUBMISSION_TRANSITIONS[terminal] == set()
    for dst in S:
        assert can_transition(terminal, dst) is False


def test_can_transition_handles_status_missing_from_table() -> None:
    # Every status is in the table today; the .get default guards against future gaps.
    assert can_transition(S.DRAFT, S.DRAFT) is False


async def test_transition_applies_status_and_stamps_submitted_at() -> None:
    session = AsyncMock()
    sub = _submission(S.READY_TO_SEND)

    result = await transition(session, sub, S.SENT)

    assert result is sub
    assert sub.status == S.SENT
    assert isinstance(sub.submitted_at, datetime)
    assert sub.submitted_at.tzinfo is UTC
    assert sub.verdict_at is None
    session.flush.assert_awaited_once()


async def test_transition_keeps_existing_submitted_at() -> None:
    session = AsyncMock()
    original = datetime(2026, 1, 1, tzinfo=UTC)
    sub = _submission(S.READY_TO_SEND)
    sub.submitted_at = original

    await transition(session, sub, S.SENT)

    assert sub.submitted_at == original


@pytest.mark.parametrize(
    "resolved",
    [S.RESOLVED_PAID, S.RESOLVED_DUP, S.RESOLVED_NA, S.RESOLVED_INFORMATIVE],
)
async def test_transition_to_resolved_stamps_verdict_at(resolved: SubmissionStatus) -> None:
    session = AsyncMock()
    sub = _submission(S.TRIAGING)

    await transition(session, sub, resolved)

    assert sub.status == resolved
    assert isinstance(sub.verdict_at, datetime)
    assert sub.submitted_at is None


async def test_transition_records_notes_only_when_given() -> None:
    session = AsyncMock()
    sub = _submission(S.TRIAGING)
    await transition(session, sub, S.RESOLVED_DUP, notes="duplicate of #123")
    assert sub.verdict_notes == "duplicate of #123"

    other = _submission(S.TRIAGING)
    other.verdict_notes = "earlier"
    await transition(session, other, S.RESOLVED_NA)
    assert other.verdict_notes == "earlier"


async def test_invalid_transition_raises_with_reason_and_leaves_submission_untouched() -> None:
    session = AsyncMock()
    sub = _submission(S.DRAFT)

    with pytest.raises(InvalidTransition) as exc_info:
        await transition(session, sub, S.SENT, notes="should not stick")

    err = exc_info.value
    assert err.from_status == S.DRAFT
    assert err.to_status == S.SENT
    assert str(err) == "Invalid submission transition: draft → sent"
    assert sub.status == S.DRAFT
    assert sub.verdict_notes is None
    session.flush.assert_not_awaited()


async def test_transition_out_of_terminal_state_is_rejected() -> None:
    session = AsyncMock()
    sub = _submission(S.RESOLVED_PAID)

    with pytest.raises(InvalidTransition, match="resolved_paid → triaging"):
        await transition(session, sub, S.TRIAGING)


async def test_transition_accepts_plain_string_status() -> None:
    # Rows loaded from the DB may carry the raw string value; tracker coerces it.
    session = AsyncMock()
    sub = _submission("draft")  # type: ignore[arg-type]

    await transition(session, sub, S.READY_TO_SEND)

    assert sub.status == S.READY_TO_SEND


# ---------------------------------------------------------------------------
# submission/payout.py
# ---------------------------------------------------------------------------


def test_severity_weights_are_monotonic() -> None:
    ordered = ["info", "low", "medium", "high", "critical"]
    weights = [SEVERITY_WEIGHTS[k] for k in ordered]
    assert weights == sorted(weights)


@pytest.mark.parametrize(
    ("min_", "max_"),
    [(None, 1000), (100, None), (None, None), (1000, 100)],
)
def test_estimate_returns_none_without_usable_bracket(min_, max_) -> None:
    assert estimate_payout("high", min_, max_) is None


def test_estimate_critical_hits_program_max() -> None:
    est = estimate_payout("critical", 100, 1000)
    assert est == PayoutEstimate(estimate=1000, low=820, high=1000, currency="USD")


def test_estimate_high_weighted_point_and_band() -> None:
    est = estimate_payout("high", 100, 1000)
    assert est is not None
    assert (est.estimate, est.low, est.high) == (685, 505, 865)


def test_estimate_info_sits_at_minimum_with_band_clamped_to_min() -> None:
    est = estimate_payout("info", 100, 1000)
    assert est is not None
    assert (est.estimate, est.low, est.high) == (100, 100, 280)


def test_estimate_severity_is_case_and_whitespace_insensitive() -> None:
    assert estimate_payout("  HIGH ", 100, 1000) == estimate_payout("high", 100, 1000)


def test_estimate_unknown_severity_falls_back_to_minimum() -> None:
    # Current behaviour: unrecognised severities silently get weight 0.0 (the minimum).
    est = estimate_payout("severe", 100, 1000)
    assert est is not None
    assert est.estimate == 100


def test_estimate_zero_width_range_collapses_to_point() -> None:
    est = estimate_payout("critical", 50, 50)
    assert est == PayoutEstimate(estimate=50, low=50, high=50, currency="USD")


def test_estimate_small_range_keeps_minimum_band_of_one() -> None:
    est = estimate_payout("medium", 0, 3)
    assert est is not None
    assert (est.estimate, est.low, est.high) == (1, 0, 2)


def test_estimate_passes_currency_through() -> None:
    est = estimate_payout("low", 10, 20, currency="EUR")
    assert est is not None
    assert est.currency == "EUR"


def test_payout_estimate_str_format() -> None:
    est = PayoutEstimate(estimate=685, low=505, high=865, currency="USD")
    assert str(est) == "~685 USD (range 505-865)"
