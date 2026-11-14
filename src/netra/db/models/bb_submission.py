"""Bug bounty submission model."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models._types import JSONB
from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.bb_program import BBProgram


class SubmissionStatus(StrEnum):
    """Submission state machine.

    Transitions (mirrors SUBMISSION_TRANSITIONS):
        draft → ready_to_send
        draft → resolved_na
        ready_to_send → sent
        ready_to_send → draft
        sent → acknowledged
        sent → resolved_na
        acknowledged → triaging
        acknowledged → resolved_na
        triaging → resolved_paid
        triaging → resolved_dup
        triaging → resolved_na
        triaging → resolved_informative
        resolved_paid, resolved_dup, resolved_na and resolved_informative are terminal.
    """

    DRAFT = "draft"
    READY_TO_SEND = "ready_to_send"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    TRIAGING = "triaging"
    RESOLVED_PAID = "resolved_paid"
    RESOLVED_DUP = "resolved_dup"
    RESOLVED_NA = "resolved_na"
    RESOLVED_INFORMATIVE = "resolved_informative"


# Allowed transitions, used by the tracker module to enforce the state machine.
SUBMISSION_TRANSITIONS: dict[SubmissionStatus, set[SubmissionStatus]] = {
    SubmissionStatus.DRAFT: {SubmissionStatus.READY_TO_SEND, SubmissionStatus.RESOLVED_NA},
    SubmissionStatus.READY_TO_SEND: {SubmissionStatus.SENT, SubmissionStatus.DRAFT},
    SubmissionStatus.SENT: {SubmissionStatus.ACKNOWLEDGED, SubmissionStatus.RESOLVED_NA},
    SubmissionStatus.ACKNOWLEDGED: {SubmissionStatus.TRIAGING, SubmissionStatus.RESOLVED_NA},
    SubmissionStatus.TRIAGING: {
        SubmissionStatus.RESOLVED_PAID,
        SubmissionStatus.RESOLVED_DUP,
        SubmissionStatus.RESOLVED_NA,
        SubmissionStatus.RESOLVED_INFORMATIVE,
    },
    # Terminal states
    SubmissionStatus.RESOLVED_PAID: set(),
    SubmissionStatus.RESOLVED_DUP: set(),
    SubmissionStatus.RESOLVED_NA: set(),
    SubmissionStatus.RESOLVED_INFORMATIVE: set(),
}


class BBSubmission(Base):
    """An H1-style submission draft tied to a finding and a program."""

    __tablename__ = "bb_submissions"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_programs.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[SubmissionStatus] = mapped_column(
        String(30), default=SubmissionStatus.DRAFT, nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    draft_md: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(120))
    payout_expected: Mapped[int | None] = mapped_column(Integer)
    payout_actual: Mapped[int | None] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    platform_report_id: Mapped[str | None] = mapped_column(String(64))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict_notes: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    program: Mapped["BBProgram"] = relationship(back_populates="submissions")
