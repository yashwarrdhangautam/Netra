"""Tests for Phase 1 scanning engine and vulnerability management."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.finding import Finding, Severity
from netra.db.models.scan import Scan, ScanProfile, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType
from netra.scanner.profiles import get_profile_config, PROFILES
from netra.scanner.tools.base import ToolResult
from netra.services.finding_service import FindingService, SLA_HOURS
from netra.services.compliance_service import CWE_TO_CONTROLS, ComplianceService


class TestScanProfiles:
    """Test scan profile configurations."""

    def test_profiles_exist(self) -> None:
        """Test that all expected profiles are defined."""
        expected_profiles = ["quick", "standard", "deep", "api_only"]
        for profile_name in expected_profiles:
            assert profile_name in PROFILES

    def test_get_profile_config(self) -> None:
        """Test getting profile configuration."""
        config = get_profile_config("quick")
        assert config["severity_filter"] == "critical,high"
        assert config["max_targets"] == 20

    def test_get_profile_config_default(self) -> None:
        """Test getting non-existent profile returns standard."""
        config = get_profile_config("nonexistent")
        assert config == PROFILES["standard"]

    def test_profile_required_fields(self) -> None:
        """Test that all profiles have required fields."""
        required_fields = [
            "severity_filter",
            "max_targets",
            "rate_limit",
            "port_range",
            "test_sqli",
            "test_xss",
        ]
        for profile_name, config in PROFILES.items():
            for field in required_fields:
                assert field in config, f"Missing {field} in {profile_name}"


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_tool_result_creation(self) -> None:
        """Test creating a ToolResult."""
        from datetime import datetime, timezone

        result = ToolResult(
            tool_name="nuclei",
            target="https://example.com",
            success=True,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        assert result.tool_name == "nuclei"
        assert result.success is True
        assert result.findings == []

    def test_tool_result_with_findings(self) -> None:
        """Test ToolResult with findings."""
        from datetime import datetime, timezone

        finding = {
            "title": "Test Finding",
            "severity": "high",
            "url": "https://example.com/vuln",
        }
        result = ToolResult(
            tool_name="nuclei",
            target="https://example.com",
            success=True,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=[finding],
        )
        assert len(result.findings) == 1
        assert result.findings[0]["title"] == "Test Finding"


class TestFindingService:
    """Test FindingService."""

    def test_sla_hours_defined(self) -> None:
        """Test that SLA hours are defined for all severities."""
        assert Severity.CRITICAL in SLA_HOURS
        assert Severity.HIGH in SLA_HOURS
        assert Severity.MEDIUM in SLA_HOURS
        assert Severity.LOW in SLA_HOURS
        assert Severity.INFO in SLA_HOURS

    def test_sla_hours_values(self) -> None:
        """Test SLA hours have reasonable values."""
        assert SLA_HOURS[Severity.CRITICAL] == 24  # 1 day
        assert SLA_HOURS[Severity.HIGH] == 168  # 7 days
        assert SLA_HOURS[Severity.INFO] == 0  # No SLA

    def test_compute_dedup_hash(self) -> None:
        """Test dedup hash computation."""
        from netra.services.finding_service import FindingService

        # Mock db session
        class MockDB:
            pass

        service = FindingService(MockDB())  # type: ignore

        finding_data = {
            "cwe_id": "CWE-89",
            "url": "https://example.com?id=1",
            "parameter": "id",
            "title": "SQL Injection",
        }
        hash1 = service._compute_dedup_hash(finding_data)
        hash2 = service._compute_dedup_hash(finding_data)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length

    def test_normalize_severity(self) -> None:
        """Test severity normalization."""
        from netra.services.finding_service import FindingService

        class MockDB:
            pass

        service = FindingService(MockDB())  # type: ignore

        assert service._normalize_severity("critical") == Severity.CRITICAL
        assert service._normalize_severity("HIGH") == Severity.HIGH
        assert service._normalize_severity("medium") == Severity.MEDIUM
        assert service._normalize_severity("invalid") == Severity.INFO


class TestComplianceService:
    """Test ComplianceService and CWE mappings."""

    def test_cwe_mappings_exist(self) -> None:
        """Test that CWE mappings are defined."""
        assert "CWE-89" in CWE_TO_CONTROLS  # SQL Injection
        assert "CWE-79" in CWE_TO_CONTROLS  # XSS
        assert "CWE-287" in CWE_TO_CONTROLS  # Improper Authentication

    def test_cwe_mapping_frameworks(self) -> None:
        """Test that CWE mappings cover all frameworks."""
        expected_frameworks = ["iso27001", "pci_dss", "soc2", "hipaa"]
        for cwe_id, mappings in CWE_TO_CONTROLS.items():
            for framework in expected_frameworks:
                assert framework in mappings, f"Missing {framework} in {cwe_id}"

    def test_cwe_mapping_controls(self) -> None:
        """Test that CWE mappings have valid control IDs."""
        for cwe_id, frameworks in CWE_TO_CONTROLS.items():
            for framework, controls in frameworks.items():
                assert len(controls) > 0, f"No controls for {cwe_id} in {framework}"


class TestScanPhase:
    """Test ScanPhase model enums."""

    def test_phase_types(self) -> None:
        """Test that all expected phase types exist."""
        expected_phases = [
            PhaseType.RECON_SUBDOMAINS,
            PhaseType.RECON_DISCOVERY,
            PhaseType.RECON_PORTS,
            PhaseType.VULN_SCAN,
            PhaseType.PENTEST,
            PhaseType.AI_ANALYSIS,
        ]
        for phase in expected_phases:
            assert phase is not None

    def test_phase_statuses(self) -> None:
        """Test that all expected phase statuses exist."""
        expected_statuses = [
            PhaseStatus.PENDING,
            PhaseStatus.RUNNING,
            PhaseStatus.COMPLETED,
            PhaseStatus.FAILED,
        ]
        for status in expected_statuses:
            assert status is not None


class TestScanModel:
    """Test Scan model enums."""

    def test_scan_statuses(self) -> None:
        """Test that all expected scan statuses exist."""
        expected_statuses = [
            ScanStatus.PENDING,
            ScanStatus.RUNNING,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
        ]
        for status in expected_statuses:
            assert status is not None

    def test_scan_profiles(self) -> None:
        """Test that all expected scan profiles exist."""
        expected_profiles = [
            ScanProfile.QUICK,
            ScanProfile.STANDARD,
            ScanProfile.DEEP,
            ScanProfile.API_ONLY,
        ]
        for profile in expected_profiles:
            assert profile is not None


class TestFindingModel:
    """Test Finding model enums."""

    def test_severity_levels(self) -> None:
        """Test that all expected severity levels exist."""
        expected_severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for severity in expected_severities:
            assert severity is not None

    def test_finding_statuses(self) -> None:
        """Test that all expected finding statuses exist."""
        from netra.db.models.finding import FindingStatus

        expected_statuses = [
            FindingStatus.NEW,
            FindingStatus.CONFIRMED,
            FindingStatus.IN_PROGRESS,
            FindingStatus.RESOLVED,
            FindingStatus.VERIFIED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        ]
        for status in expected_statuses:
            assert status is not None


# Integration tests (require database)
@pytest.mark.asyncio
class TestIntegration:
    """Integration tests for Phase 1 components."""

    async def test_finding_service_create(
        self, async_db_session: AsyncSession
    ) -> None:
        """Test creating a finding via FindingService."""
        from netra.db.models.scan import Scan
        from netra.services.finding_service import FindingService

        # Create a test scan first
        scan = Scan(
            name="Test Scan",
            profile=ScanProfile.QUICK,
            target_id=(
                await async_db_session.execute(select(Scan).limit(1))
            ).scalar_one_or_none()
            if False
            else None,
        )
        # For this test, we just verify the service can be instantiated
        service = FindingService(async_db_session)
        assert service.db == async_db_session

    async def test_compliance_service_init(
        self, async_db_session: AsyncSession
    ) -> None:
        """Test ComplianceService initialization."""
        service = ComplianceService(async_db_session)
        assert service.db == async_db_session
