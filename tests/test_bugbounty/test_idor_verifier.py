"""Tests for the non-destructive IDOR verifier (Sprint 2)."""

import pytest

from netra.bugbounty.verifiers.idor import IdorVerificationError, verify_idor


def _allow(_url: str) -> bool:
    return True


def _transport(status: int, body: str):
    async def t(method: str, url: str, headers: dict[str, str]):
        return (status, body)

    return t


@pytest.mark.asyncio
async def test_confirmed_idor():
    r = await verify_idor(
        method="GET",
        url="https://app.test/api/invoices/1043",
        attacker_headers={"Authorization": "Bearer attacker"},
        owner_marker="acct_victim_77",
        transport=_transport(200, '{"id":1043,"account":"acct_victim_77"}'),
        scope_check=_allow,
    )
    assert r.confirmed is True
    assert r.status_code == 200
    assert r.evidence["owner_marker_present"] is True


@pytest.mark.asyncio
async def test_denied_is_not_idor():
    r = await verify_idor(
        method="GET",
        url="https://app.test/api/invoices/1043",
        attacker_headers={},
        owner_marker="acct_victim_77",
        transport=_transport(403, "forbidden"),
        scope_check=_allow,
    )
    assert r.confirmed is False
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_accessible_without_marker_is_not_idor():
    r = await verify_idor(
        method="GET",
        url="https://app.test/api/invoices/1043",
        attacker_headers={},
        owner_marker="acct_victim_77",
        transport=_transport(200, '{"id":1043,"account":"acct_attacker_self"}'),
        scope_check=_allow,
    )
    assert r.confirmed is False


@pytest.mark.asyncio
async def test_non_destructive_guard_rejects_writes():
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        with pytest.raises(IdorVerificationError):
            await verify_idor(
                method=verb,
                url="https://app.test/api/invoices/1043",
                attacker_headers={},
                owner_marker="x",
                transport=_transport(200, ""),
                scope_check=_allow,
            )


@pytest.mark.asyncio
async def test_scope_gate_blocks_out_of_scope():
    with pytest.raises(IdorVerificationError):
        await verify_idor(
            method="GET",
            url="https://evil.test/api/1",
            attacker_headers={},
            owner_marker="x",
            transport=_transport(200, "x"),
            scope_check=lambda _u: False,
        )


@pytest.mark.asyncio
async def test_requires_owner_marker():
    with pytest.raises(IdorVerificationError):
        await verify_idor(
            method="GET",
            url="https://app.test/1",
            attacker_headers={},
            owner_marker="",
            transport=_transport(200, "x"),
            scope_check=_allow,
        )
