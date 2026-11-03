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


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _ev(kind=HuntEventKind.ACTION, agent="A-1"):
    return HuntEvent(hunt_id="h", phase=HuntPhase.ATTACK, kind=kind, agent_id=agent, message="m")


def test_aggregator_high_signal_always_passes():
    from netra.api.hunt_events import EventAggregator

    ag = EventAggregator(window=1, max_per_window=1, now=_Clock())
    assert ag.offer(_ev(HuntEventKind.HIT)) is True
    for _ in range(5):
        assert ag.offer(_ev(HuntEventKind.PROVE)) is True  # never rate-capped


def test_aggregator_coalesces_low_signal_within_window():
    from netra.api.hunt_events import EventAggregator

    ag = EventAggregator(window=1, max_per_window=10, now=_Clock())
    assert ag.offer(_ev(agent="A-1")) is True
    assert ag.offer(_ev(agent="A-1")) is False  # same agent+kind -> coalesced
    assert ag.offer(_ev(agent="A-2")) is True  # different agent passes


def test_aggregator_rate_cap():
    from netra.api.hunt_events import EventAggregator

    ag = EventAggregator(window=1, max_per_window=2, now=_Clock())
    assert ag.offer(_ev(agent="A-1")) is True
    assert ag.offer(_ev(agent="A-2")) is True
    assert ag.offer(_ev(agent="A-3")) is False  # cap reached


def test_aggregator_window_reset():
    from netra.api.hunt_events import EventAggregator

    clk = _Clock()
    ag = EventAggregator(window=1, max_per_window=1, now=clk)
    assert ag.offer(_ev(agent="A-1")) is True
    assert ag.offer(_ev(agent="A-2")) is False  # cap
    clk.t = 1.5  # advance past the window
    assert ag.offer(_ev(agent="A-2")) is True  # counters reset
