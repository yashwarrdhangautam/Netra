"""Tests for findings API endpoints."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_findings_empty(client: AsyncClient) -> None:
    """Test listing findings when empty."""
    response = await client.get("/api/v1/findings/")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_create_finding_requires_auth(client: AsyncClient) -> None:
    """Test that creating a finding requires authentication."""
    payload = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "title": "Test Finding",
        "description": "Test description",
        "severity": "medium",
        "tool_source": "test",
    }
    response = await client.post("/api/v1/findings/", json=payload)

    # Should fail without auth token
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_get_finding_not_found(client: AsyncClient) -> None:
    """Test getting a non-existent finding."""
    finding_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(f"/api/v1/findings/{finding_id}")

    assert response.status_code == 404
