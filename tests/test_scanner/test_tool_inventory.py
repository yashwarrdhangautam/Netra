"""Scanner tool inventory: installed state, required-vs-optional split, and the API route."""

import pytest

from netra.scanner.tools import inventory
from netra.scanner.tools.inventory import TOOL_SPECS, missing_required_tools, tool_inventory


def test_every_wrapper_binary_is_inventoried():
    """Each binary the scanner wrappers call by name must appear in the inventory."""
    wrapper_binaries = {
        "amass", "assetfinder", "checkov", "dalfox", "pip-audit", "dnsx", "ffuf", "gau",
        "gitleaks", "httpx", "katana", "garak", "naabu", "nikto", "nmap", "nuclei",
        "prowler", "recontool", "semgrep", "shodan", "sqlmap", "subfinder", "subzy",
        "trivy", "wpscan",
    }  # fmt: skip
    inventoried = {spec.binary for spec in TOOL_SPECS}
    assert wrapper_binaries <= inventoried


def test_binaries_are_unique():
    binaries = [spec.binary for spec in TOOL_SPECS]
    assert len(binaries) == len(set(binaries))


def test_missing_binary_reported_as_not_installed(monkeypatch):
    monkeypatch.setattr(inventory, "_resolve", lambda binary: None)
    rows = tool_inventory()
    assert rows and all(row["installed"] is False for row in rows)
    assert all(row["path"] is None for row in rows)


def test_missing_required_excludes_optional(monkeypatch):
    monkeypatch.setattr(inventory, "_resolve", lambda binary: None)
    missing = missing_required_tools()
    optional = {spec.binary for spec in TOOL_SPECS if spec.optional}
    assert not set(missing) & optional
    assert "nikto" in missing and "sqlmap" in missing


def test_installed_binary_reports_path(monkeypatch):
    monkeypatch.setattr(inventory, "_resolve", lambda binary: f"/usr/local/bin/{binary}")
    row = next(r for r in tool_inventory() if r["binary"] == "nmap")
    assert row["installed"] is True
    assert row["path"] == "/usr/local/bin/nmap"


@pytest.mark.asyncio
async def test_route_uses_worker_inventory(monkeypatch):
    from netra.api.routes import scanner_tools

    fake = [
        {"binary": "nmap", "installed": True, "optional": False},
        {"binary": "nikto", "installed": False, "optional": False},
        {"binary": "wpscan", "installed": False, "optional": True},
    ]
    monkeypatch.setattr(scanner_tools, "_worker_inventory", lambda: fake)
    body = await scanner_tools.list_scanner_tools()
    assert body["source"] == "worker"
    assert body["missing_required"] == ["nikto"]
    assert body["missing_count"] == 1
    assert len(body["tools"]) == 3


@pytest.mark.asyncio
async def test_route_falls_back_to_api_when_no_worker(monkeypatch):
    from netra.api.routes import scanner_tools

    def no_worker():
        raise TimeoutError("no worker answered")

    monkeypatch.setattr(scanner_tools, "_worker_inventory", no_worker)
    monkeypatch.setattr(
        scanner_tools,
        "tool_inventory",
        lambda: [
            {"binary": "nmap", "installed": True, "optional": False},
        ],
    )
    body = await scanner_tools.list_scanner_tools()
    assert body["source"] == "api"
    assert body["missing_count"] == 0
