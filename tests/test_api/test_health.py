"""Tests for health check endpoint."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    """Test health check endpoint returns ok status."""
    response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "db" in data


@pytest.mark.asyncio
async def test_health_check_version(client: AsyncClient) -> None:
    """Test health check returns version."""
    response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "0.1.0"
