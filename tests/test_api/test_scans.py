"""Tests for scans API endpoints."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_scans_empty(client: AsyncClient) -> None:
    """Test listing scans when empty."""
    response = await client.get("/api/v1/scans/")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_create_scan_requires_auth(client: AsyncClient) -> None:
    """Test that creating a scan requires authentication."""
    payload = {
        "target_id": "00000000-0000-0000-0000-000000000000",
        "name": "Test Scan",
        "profile": "standard",
    }
    response = await client.post("/api/v1/scans/", json=payload)

    # Should fail without auth token
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_get_scan_not_found(client: AsyncClient) -> None:
    """Test getting a non-existent scan."""
    scan_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 404
