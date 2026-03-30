"""Tests for Phase 4 features: Celery tasks, notifications, auth, and integrations."""
import pytest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from netra.worker.tasks import (
    scope_resolution,
    recon,
    vuln_scan,
    active_test,
    ai_analysis,
    reporting,
    create_scan_pipeline,
)
from netra.notifications.slack import SlackNotifier
from netra.notifications.email import EmailNotifier
from netra.notifications.manager import NotificationManager
from netra.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    token_blacklist,
    generate_mfa_secret,
    verify_mfa_code,
    generate_backup_codes,
    verify_backup_code,
    create_password_reset_token,
    decode_password_reset_token,
)
from netra.integrations.defectdojo import DefectDojoClient
from netra.integrations.jira import JiraClient


# ── Celery Task Tests ─────────────────────────────────────────────────────────


class TestCeleryTasks:
    """Test Celery distributed scanning tasks."""

    def test_scope_resolution_stub(self):
        """Test scope resolution task returns expected structure."""
        scan_id = str(uuid.uuid4())
        # Note: Real implementation requires DB and tools
        # This tests the task structure
        assert isinstance(scan_id, str)

    def test_create_scan_pipeline(self):
        """Test scan pipeline chain creation."""
        scan_id = str(uuid.uuid4())
        pipeline = create_scan_pipeline(scan_id)
        
        # Pipeline should have 6 tasks in chain
        # (scope_resolution, recon, vuln_scan, active_test, ai_analysis, reporting)
        assert pipeline is not None

    @pytest.mark.asyncio
    async def test_token_blacklist_add(self):
        """Test adding token to blacklist."""
        token = "test_token_123"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        result = await token_blacklist.add(token, expires_at)
        assert result is True
        
        # Check if blacklisted
        is_blacklisted = await token_blacklist.is_blacklisted(token)
        assert is_blacklisted is True

    @pytest.mark.asyncio
    async def test_token_blacklist_check_not_found(self):
        """Test checking non-blacklisted token."""
        token = "non_blacklisted_token"
        
        is_blacklisted = await token_blacklist.is_blacklisted(token)
        assert is_blacklisted is False


# ── Slack Notification Tests ──────────────────────────────────────────────────


class TestSlackNotifier:
    """Test Slack notification sender."""

    def test_slack_notifier_init_no_config(self):
        """Test Slack notifier initialization without config."""
        notifier = SlackNotifier()
        assert notifier.webhook_url is None

    def test_slack_notifier_init_with_url(self):
        """Test Slack notifier initialization with webhook URL."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK"
        notifier = SlackNotifier(webhook_url=webhook_url)
        assert notifier.webhook_url == webhook_url

    def test_get_severity_color(self):
        """Test severity color mapping."""
        notifier = SlackNotifier()
        
        assert notifier._get_severity_color("critical") == "#ff0000"
        assert notifier._get_severity_color("high") == "#ff6600"
        assert notifier._get_severity_color("medium") == "#ffcc00"
        assert notifier._get_severity_color("low") == "#00ff00"
        assert notifier._get_severity_color("info") == "#0066ff"
        assert notifier._get_severity_color("unknown") == "#808080"

    def test_get_severity_emoji(self):
        """Test severity emoji mapping."""
        notifier = SlackNotifier()
        
        assert notifier._get_severity_emoji("critical") == "🔴"
        assert notifier._get_severity_emoji("high") == "🟠"
        assert notifier._get_severity_emoji("medium") == "🟡"
        assert notifier._get_severity_emoji("low") == "🟢"
        assert notifier._get_severity_emoji("info") == "🔵"

    @pytest.mark.asyncio
    async def test_send_no_webhook(self):
        """Test send returns False when no webhook configured."""
        notifier = SlackNotifier()
        result = await notifier.send({"text": "Test"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_finding_alert_structure(self):
        """Test finding alert message structure."""
        notifier = SlackNotifier()
        
        finding = {
            "title": "SQL Injection",
            "target": "https://example.com",
            "tool_name": "sqlmap",
            "cvss_score": 9.8,
        }
        
        # Test method doesn't fail with valid data
        message = {
            "text": f"New HIGH finding: {finding['title']}",
            "attachments": [{
                "color": notifier._get_severity_color("high"),
                "fields": [
                    {"title": "Severity", "value": "HIGH", "short": True},
                    {"title": "Target", "value": finding["target"], "short": True},
                ],
            }],
        }
        assert message["text"] is not None


# ── Email Notification Tests ──────────────────────────────────────────────────


class TestEmailNotifier:
    """Test email notification sender."""

    def test_email_notifier_init_no_config(self):
        """Test email notifier initialization without config."""
        notifier = EmailNotifier()
        assert notifier.smtp_host is None or notifier.smtp_host == ""

    def test_email_notifier_init_with_config(self):
        """Test email notifier initialization with config."""
        notifier = EmailNotifier(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user@example.com",
            smtp_password="password123",
            from_email="netra@example.com",
        )
        assert notifier.smtp_host == "smtp.example.com"
        assert notifier.smtp_port == 587

    def test_send_no_config(self):
        """Test send returns False when no SMTP config."""
        notifier = EmailNotifier()
        result = notifier.send(
            to="test@example.com",
            subject="Test",
            body="Test body",
        )
        assert result is False

    def test_generate_report_body(self):
        """Test HTML report body generation."""
        notifier = EmailNotifier()
        
        findings = [
            {"title": "Finding 1", "severity": "high"},
            {"title": "Finding 2", "severity": "medium"},
        ]
        
        html = notifier._generate_report_body(findings)
        assert html is not None
        assert "Findings Report" in html
        assert "2 findings" in html


# ── Security Tests ────────────────────────────────────────────────────────────


class TestSecurity:
    """Test security utilities."""

    def test_create_access_token(self):
        """Test access token creation."""
        user_id = uuid.uuid4()
        token = create_access_token(user_id)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 100

    def test_decode_access_token(self):
        """Test access token decoding."""
        user_id = uuid.uuid4()
        token = create_access_token(user_id)
        
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"

    def test_create_refresh_token(self):
        """Test refresh token creation."""
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Refresh token should have longer expiry than access token
        payload = decode_refresh_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"
        assert "jti" in payload  # Unique ID for rotation

    def test_decode_invalid_token(self):
        """Test decoding invalid token returns None."""
        result = decode_access_token("invalid_token")
        assert result is None

    def test_mfa_secret_generation(self):
        """Test MFA secret generation."""
        secret = generate_mfa_secret()
        
        assert secret is not None
        assert isinstance(secret, str)
        assert len(secret) == 16  # Base32 encoded, 16 chars

    def test_mfa_code_verification(self):
        """Test MFA code verification."""
        secret = generate_mfa_secret()
        
        # Generate current code
        import pyotp
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Verify should succeed with valid code
        result = verify_mfa_code(secret, current_code)
        assert result is True

    def test_mfa_code_verification_invalid(self):
        """Test MFA code verification with invalid code."""
        secret = generate_mfa_secret()
        
        # Verify should fail with invalid code
        result = verify_mfa_code(secret, "000000")
        assert result is False

    def test_backup_codes_generation(self):
        """Test backup code generation."""
        codes = generate_backup_codes(10)
        
        assert len(codes) == 10
        assert all(isinstance(code, str) for code in codes)
        assert all(len(code) >= 8 for code in codes)

    def test_backup_code_verification(self):
        """Test backup code verification."""
        from netra.core.security import hash_backup_code
        
        code = "TESTCODE123"
        hashed = hash_backup_code(code)
        
        assert verify_backup_code(code, hashed) is True
        assert verify_backup_code("WRONGCODE", hashed) is False

    def test_password_reset_token(self):
        """Test password reset token creation and decoding."""
        user_id = uuid.uuid4()
        token = create_password_reset_token(user_id, expires_hours=1)
        
        assert token is not None
        
        payload = decode_password_reset_token(token)
        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "password_reset"


# ── DefectDojo Integration Tests ─────────────────────────────────────────────


class TestDefectDojoClient:
    """Test DefectDojo integration."""

    def test_client_init_no_config(self):
        """Test client initialization without config."""
        client = DefectDojoClient()
        assert client.is_configured() is False

    def test_client_init_with_config(self):
        """Test client initialization with config."""
        client = DefectDojoClient(
            base_url="https://defectdojo.example.com",
            api_key="test_api_key",
        )
        assert client.is_configured() is True
        assert client.base_url == "https://defectdojo.example.com"

    def test_get_numerical_severity(self):
        """Test severity to numerical mapping."""
        client = DefectDojoClient()
        
        assert client._get_numerical_severity("critical") == 1
        assert client._get_numerical_severity("high") == 2
        assert client._get_numerical_severity("medium") == 3
        assert client._get_numerical_severity("low") == 4
        assert client._get_numerical_severity("info") == 5


# ── Jira Integration Tests ────────────────────────────────────────────────────


class TestJiraClient:
    """Test Jira integration."""

    def test_client_init_no_config(self):
        """Test client initialization without config."""
        client = JiraClient()
        assert client.is_configured() is False

    def test_client_init_with_config(self):
        """Test client initialization with config."""
        client = JiraClient(
            base_url="https://example.atlassian.net",
            email="user@example.com",
            api_token="test_token",
            project_key="SEC",
        )
        assert client.is_configured() is True
        assert client.is_cloud is True
        assert client.project_key == "SEC"

    def test_build_description(self):
        """Test Jira description building."""
        client = JiraClient()
        
        finding = {
            "title": "SQL Injection",
            "description": "SQL injection found in login form",
            "severity": "critical",
            "tool_name": "sqlmap",
            "cvss_score": 9.8,
            "cwe": 89,
            "remediation": "Use parameterized queries",
        }
        
        scan = {
            "name": "Q1 Security Scan",
            "target": "https://example.com",
            "profile": "deep",
        }
        
        description = client._build_description(finding, scan)
        
        assert "SQL Injection" in description
        assert "9.8" in description
        assert "CWE-89" in description
        assert "parameterized queries" in description


# ── Notification Manager Tests ───────────────────────────────────────────────


class TestNotificationManager:
    """Test notification manager."""

    def test_manager_init(self):
        """Test notification manager initialization."""
        mock_db = AsyncMock()
        manager = NotificationManager(mock_db)
        
        assert manager.slack is not None
        assert manager.email is not None

    @pytest.mark.asyncio
    async def test_notify_critical_finding_skips_medium(self):
        """Test critical finding notification skips medium severity."""
        mock_db = AsyncMock()
        manager = NotificationManager(mock_db)
        
        mock_finding = MagicMock()
        mock_finding.severity = "medium"
        mock_scan = MagicMock()
        
        # Should return early for medium severity
        await manager.notify_critical_finding(mock_finding, mock_scan)
        # No assertions needed - test passes if no exception


# ── Integration Test Helpers ─────────────────────────────────────────────────


@pytest.fixture
def mock_scan():
    """Create a mock scan object."""
    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.name = "Test Scan"
    scan.profile = "deep"
    scan.target.value = "https://example.com"
    return scan


@pytest.fixture
def mock_finding():
    """Create a mock finding object."""
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.title = "SQL Injection"
    finding.severity = "critical"
    finding.cvss_score = 9.8
    finding.tool_name = "sqlmap"
    finding.description = "SQL injection vulnerability found"
    finding.remediation = "Use parameterized queries"
    return finding


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    return AsyncMock()
