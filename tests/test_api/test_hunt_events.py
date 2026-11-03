"""Tests for the live-hunt event contract + reconnect buffer (ADR-004 / Sprint 5)."""

import pytest
from pydantic import ValidationError

from netra.api.hunt_events import (
    HuntEvent,
    HuntEventBuffer,
    HuntEventKind,
    HuntPhase,
    OperatorCmd,
    OperatorCommand,
    Severity,
)


def _mk(msg="x", **kw):
    return HuntEvent(
        hunt_id="h1", phase=HuntPhase.ATTACK, kind=HuntEventKind.ACTION, message=msg, **kw
    )


def test_event_defaults():
    e = _mk()
    assert e.v == 1 and e.seq == 0 and e.refs == [] and e.severity is None and e.ts is not None


def test_event_requires_core_fields():
    with pytest.raises(ValidationError):
        HuntEvent(hunt_id="h1")  # missing phase/kind/message


def test_buffer_assigns_monotonic_seq():
    b = HuntEventBuffer()
    a = b.append(_mk("a"))
    c = b.append(_mk("b"))
    assert a.seq == 1 and c.seq == 2 and b.last_seq == 2 and len(b) == 2


def test_replay_since_returns_tail():
    b = HuntEventBuffer()
    for i in range(5):
        b.append(_mk(str(i)))
    r = b.replay_since(3)
    assert [e.seq for e in r.events] == [4, 5] and r.resync_required is False


def test_replay_since_zero_returns_all():
    b = HuntEventBuffer()
    for i in range(3):
        b.append(_mk(str(i)))
    assert len(b.replay_since(0).events) == 3


def test_replay_resync_when_behind_window():
    b = HuntEventBuffer(maxlen=3)
    for i in range(10):
        b.append(_mk(str(i)))  # seqs 1..10, retains 8,9,10
    r = b.replay_since(2)  # 3 < floor(8) -> client missed evicted events
    assert r.resync_required is True and len(r.events) == 3


def test_replay_at_window_edge_no_resync():
    b = HuntEventBuffer(maxlen=3)
    for i in range(10):
        b.append(_mk(str(i)))  # retains 8,9,10
    r = b.replay_since(7)  # next expected is 8, exactly the floor -> no gap
    assert r.resync_required is False and [e.seq for e in r.events] == [8, 9, 10]


def test_operator_command_validates():
    c = OperatorCommand(cmd=OperatorCmd.PROMOTE_FINDING, hunt_id="h1", target="fnd_1", nonce="n")
    assert c.cmd == "promote_finding"
    with pytest.raises(ValidationError):
        OperatorCommand(cmd="nonsense", hunt_id="h1", nonce="n")


def test_severity_and_refs():
    e = _mk(severity=Severity.HIGH, refs=[{"type": "finding", "id": "fnd_1"}])
    assert e.severity == "high" and e.refs[0].type == "finding"
