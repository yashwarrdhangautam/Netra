"""Typed live-hunt event contract + reconnect buffer (ADR-004).

Server -> client: HuntEvent, append-only with a monotonic per-hunt seq.
Client -> server: OperatorCommand, authz-checked and audited by the caller.
HuntEventBuffer assigns seq, retains a bounded window, and replays from a
client's Last-Event-ID so a reconnecting console can resync without a gap.

message carries plain text only; emphasis/colour is derived client-side from
kind/severity (never embedded as markup) so the console can render text-only.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class HuntPhase(StrEnum):
    LEARN = "learn"
    MAP = "map"
    COORDINATE = "coordinate"
    ATTACK = "attack"
    PROVE = "prove"
    VERIFY = "verify"


class HuntEventKind(StrEnum):
    DISPATCH = "dispatch"
    ACTION = "action"
    HIT = "hit"
    PROVE = "prove"
    BLOCK = "block"
    CITE = "cite"
    COST = "cost"
    PHASE_CHANGE = "phase_change"
    AGENT_RETIRED = "agent_retired"
    STATUS = "status"


class Severity(StrEnum):
    CRITICAL = "crit"
    HIGH = "high"
    MEDIUM = "med"
    LOW = "low"
    INFO = "info"


class EventRef(BaseModel):
    type: str
    id: str | None = None
    value: str | None = None


class HuntEvent(BaseModel):
    v: int = 1
    seq: int = 0  # assigned by the buffer on append
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hunt_id: str
    agent_id: str | None = None
    phase: HuntPhase
    kind: HuntEventKind
    severity: Severity | None = None
    message: str
    refs: list[EventRef] = Field(default_factory=list)


class OperatorCmd(StrEnum):
    APPROVE_RUN = "approve_run"
    PAUSE_AGENT = "pause_agent"
    KILL_AGENT = "kill_agent"
    PAUSE_HUNT = "pause_hunt"
    RESUME_HUNT = "resume_hunt"
    PROMOTE_FINDING = "promote_finding"


class OperatorCommand(BaseModel):
    cmd: OperatorCmd
    hunt_id: str
    target: str | None = None  # agent id or finding id, depending on cmd
    nonce: str


class ReplayResult(BaseModel):
    events: list[HuntEvent]
    resync_required: bool = False  # True when last_seq predates the retained window


class HuntEventBuffer:
    """Bounded, monotonic event log for one hunt, with reconnect replay."""

    def __init__(self, maxlen: int = 2000) -> None:
        self._events: deque[HuntEvent] = deque(maxlen=maxlen)
        self._seq = 0

    @property
    def last_seq(self) -> int:
        return self._seq

    def __len__(self) -> int:
        return len(self._events)

    def append(self, event: HuntEvent) -> HuntEvent:
        self._seq += 1
        event.seq = self._seq
        if event.v < 1:
            event.v = 1
        self._events.append(event)
        return event

    def replay_since(self, last_seq: int) -> ReplayResult:
        """Return events with seq > last_seq.

        If last_seq is older than the oldest retained event (the client missed
        evicted events), signal a full resync and return the whole window.
        """
        if not self._events:
            return ReplayResult(events=[], resync_required=False)
        floor = self._events[0].seq
        if last_seq + 1 < floor:
            return ReplayResult(events=list(self._events), resync_required=True)
        return ReplayResult(
            events=[e for e in self._events if e.seq > last_seq], resync_required=False
        )
