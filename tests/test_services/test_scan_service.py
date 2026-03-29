"""Tests for scan service."""
import pytest

from netra.db.models import Scan, ScanProfile, ScanStatus, Target, TargetType
from netra.services.scan_service import ScanService


@pytest.mark.asyncio
async def test_scan_service_stub(db_session) -> None:
    """Test scan service stub."""
    service = ScanService(db_session)
    # Phase 1: implement real service
    assert service is not None
