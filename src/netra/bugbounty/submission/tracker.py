"""Submission state machine — enforces valid transitions on bb_submissions.status."""
from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.bb_submission import (
    SUBMISSION_TRANSITIONS,
    BBSubmission,
    SubmissionStatus,
)

logger = structlog.get_logger()


class InvalidTransition(Exception):
    """Raised when an attempted state transition isn't allowed."""

    def __init__(self, from_status: SubmissionStatus, to_status: SubmissionStatus):
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Invalid submission transition: {from_status.value} → {to_status.value}"
        )


def can_transition(
    from_status: SubmissionStatus, to_status: SubmissionStatus
) -> bool:
    """Return True if the transition is allowed."""
    return to_status in SUBMISSION_TRANSITIONS.get(from_status, set())


async def transition(
    session: AsyncSession,
    submission: BBSubmission,
    to_status: SubmissionStatus,
    notes: str | None = None,
) -> BBSubmission:
    """Apply a state transition to a submission. Raises InvalidTransition on miss.

    Caller is responsible for the surrounding transaction.
    """
    current = SubmissionStatus(submission.status)
    if not can_transition(current, to_status):
        raise InvalidTransition(current, to_status)

    logger.info(
        "bb.submission.transition",
        submission_id=str(submission.id),
        from_status=current.value,
        to_status=to_status.value,
    )

    submission.status = to_status
    if notes:
        submission.verdict_notes = notes

    # Stamp times where appropriate.
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if to_status == SubmissionStatus.SENT and submission.submitted_at is None:
        submission.submitted_at = now
    if to_status in {
        SubmissionStatus.RESOLVED_PAID,
        SubmissionStatus.RESOLVED_DUP,
        SubmissionStatus.RESOLVED_NA,
        SubmissionStatus.RESOLVED_INFORMATIVE,
    }:
        submission.verdict_at = now

    await session.flush()
    return submission
