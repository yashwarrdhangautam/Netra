"""Tests for targets API endpoints."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_targets_empty(client: AsyncClient) -> None:
    """Test listing targets when empty."""
    response = await client.get("/api/v1/targets/")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_create_target_requires_auth(client: AsyncClient) -> None:
    """Test that creating a target requires authentication."""
    payload = {
        "name": "Test Target",
        "target_type": "domain",
        "value": "example.com",
    }
    response = await client.post("/api/v1/targets/", json=payload)

    # Should fail without auth token
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_get_target_not_found(client: AsyncClient) -> None:
    """Test getting a non-existent target."""
    target_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(f"/api/v1/targets/{target_id}")

    assert response.status_code == 404
