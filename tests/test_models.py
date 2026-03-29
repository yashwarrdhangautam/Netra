"""Tests for database models."""
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models import Scan, ScanProfile, ScanStatus, Target, TargetType


@pytest.mark.asyncio
async def test_create_target(db_session: AsyncSession) -> None:
    """Test creating a target."""
    target = Target(
        name="Test Target",
        target_type=TargetType.DOMAIN,
        value="example.com",
    )
    db_session.add(target)
    await db_session.flush()

    assert target.id is not None
    assert target.name == "Test Target"
    assert target.target_type == TargetType.DOMAIN
    assert target.value == "example.com"


@pytest.mark.asyncio
async def test_create_scan(db_session: AsyncSession) -> None:
    """Test creating a scan."""
    # Create target first
    target = Target(
        name="Test Target",
        target_type=TargetType.DOMAIN,
        value="example.com",
    )
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Test Scan",
        profile=ScanProfile.STANDARD,
        target_id=target.id,
    )
    db_session.add(scan)
    await db_session.flush()

    assert scan.id is not None
    assert scan.name == "Test Scan"
    assert scan.profile == ScanProfile.STANDARD
    assert scan.status == ScanStatus.PENDING
    assert scan.target_id == target.id


@pytest.mark.asyncio
async def test_scan_target_relationship(db_session: AsyncSession) -> None:
    """Test scan-target relationship."""
    target = Target(
        name="Test Target",
        target_type=TargetType.DOMAIN,
        value="example.com",
    )
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Test Scan",
        profile=ScanProfile.STANDARD,
        target_id=target.id,
    )
    db_session.add(scan)
    await db_session.flush()

    # Refresh to load relationships
    await db_session.refresh(target, ["scans"])
    await db_session.refresh(scan, ["target"])

    assert len(target.scans) == 1
    assert scan.target.id == target.id
