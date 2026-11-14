"""Scan manifest route: built from recorded recon hosts, same visibility rules as the scan itself."""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from netra.api.routes import intel
from netra.intel.manifest import validate_manifest

HOSTS = [
    {
        "url": "https://app.example.org",
        "hostname": "app.example.org",
        "status_code": 200,
        "title": "App",
        "tech": ["nginx"],
        "protections": ["waf"],
    }
]


class FakeDb:
    def __init__(self, scan):
        self._scan = scan

    async def get(self, model, key):
        return self._scan


async def _visible(*_args, **_kwargs):
    return True


async def _hidden(*_args, **_kwargs):
    return False


async def test_manifest_json_is_valid(monkeypatch):
    scan = SimpleNamespace(name="example", checkpoint_data={"http_hosts": HOSTS})
    monkeypatch.setattr(intel, "can_see_scan", _visible)
    body = await intel.scan_manifest(
        scan_id=uuid.uuid4(), current_user=None, output="json", db=FakeDb(scan)
    )
    assert validate_manifest(body) == []
    assert body["counts"]["live"] == 1


async def test_manifest_markdown_is_arsenal_map(monkeypatch):
    scan = SimpleNamespace(name="example", checkpoint_data={"http_hosts": HOSTS})
    monkeypatch.setattr(intel, "can_see_scan", _visible)
    response = await intel.scan_manifest(
        scan_id=uuid.uuid4(), current_user=None, output="markdown", db=FakeDb(scan)
    )
    assert "Arsenal map" in response.body.decode()


async def test_hidden_scan_is_404(monkeypatch):
    scan = SimpleNamespace(name="example", checkpoint_data={"http_hosts": HOSTS})
    monkeypatch.setattr(intel, "can_see_scan", _hidden)
    with pytest.raises(HTTPException) as exc:
        await intel.scan_manifest(
            scan_id=uuid.uuid4(), current_user=None, output="json", db=FakeDb(scan)
        )
    assert exc.value.status_code == 404


async def test_scan_without_recorded_hosts_is_409(monkeypatch):
    scan = SimpleNamespace(name="example", checkpoint_data={})
    monkeypatch.setattr(intel, "can_see_scan", _visible)
    with pytest.raises(HTTPException) as exc:
        await intel.scan_manifest(
            scan_id=uuid.uuid4(), current_user=None, output="json", db=FakeDb(scan)
        )
    assert exc.value.status_code == 409
