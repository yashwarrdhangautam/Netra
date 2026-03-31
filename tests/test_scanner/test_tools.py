"""Tests for scanner tool wrappers."""
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from netra.scanner.tools.nmap import NmapTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.scanner.tools.base import ToolResult


@pytest.fixture
def temp_work_dir(tmp_path):
    """Create a temporary work directory."""
    work_dir = tmp_path / "scanner_test"
    work_dir.mkdir()
    yield work_dir


class TestNmapTool:
    """Tests for NmapTool wrapper."""

    @pytest.mark.asyncio
    async def test_nmap_run_success(self, temp_work_dir):
        """Test Nmap scan with successful execution."""
        tool = NmapTool(work_dir=temp_work_dir)

        # Mock _execute_command
        mock_stdout = """
        Starting Nmap 7.94
        Nmap scan report for scanme.nmap.org (45.33.32.156)
        Host is up (0.045s latency).
        
        PORT   STATE SERVICE VERSION
        22/tcp open  ssh     OpenSSH 7.9p1
        80/tcp open  http    Apache httpd 2.4.41
        
        Nmap done: 1 IP address (1 host up) scanned in 10.45s
        """

        # Create mock XML output
        xml_content = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="45.33.32.156" addrtype="ipv4"/>
                <hostnames><hostname name="scanme.nmap.org"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open" reason="syn-ack"/>
                        <service name="ssh" product="OpenSSH" version="7.9p1"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack"/>
                        <service name="http" product="Apache" version="2.4.41"/>
                        <script id="http-title" output="Apache Default Page"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        xml_file = temp_work_dir / "nmap_output.xml"
        xml_file.write_text(xml_content)

        async def mock_execute(cmd, timeout=3600):
            return 0, mock_stdout, ""

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("scanme.nmap.org", ports="top-100")

            assert result.tool_name == "nmap"
            assert result.target == "scanme.nmap.org"
            assert result.success is True
            assert len(result.findings) > 0
            assert result.metadata["ports"] == "top-100"

    @pytest.mark.asyncio
    async def test_nmap_run_failure(self, temp_work_dir):
        """Test Nmap scan with failure."""
        tool = NmapTool(work_dir=temp_work_dir)

        async def mock_execute(cmd, timeout=3600):
            return -1, "", "nmap: command not found"

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("scanme.nmap.org")

            assert result.success is False
            assert result.error is not None
            assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_nmap_is_installed(self, temp_work_dir):
        """Test Nmap installation check."""
        tool = NmapTool(work_dir=temp_work_dir)

        with patch("netra.scanner.tools.nmap.shutil.which", return_value="/usr/bin/nmap"):
            assert tool.is_installed() is True

        with patch("netra.scanner.tools.nmap.shutil.which", return_value=None):
            assert tool.is_installed() is False

    def test_nmap_parse_xml_output(self, temp_work_dir):
        """Test Nmap XML output parsing."""
        tool = NmapTool(work_dir=temp_work_dir)

        xml_content = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <hostnames><hostname name="router.local"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https" product="nginx" version="1.18.0"/>
                        <script id="ssl-heartbleed" output="VULNERABLE: Heartbleed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        xml_file = temp_work_dir / "test.xml"
        xml_file.write_text(xml_content)

        findings = tool._parse_xml_output(str(xml_file), "192.168.1.1")

        assert len(findings) >= 1
        assert any("Heartbleed" in str(f) for f in findings)

    def test_nmap_extract_cves(self, temp_work_dir):
        """Test CVE extraction from text."""
        tool = NmapTool(work_dir=temp_work_dir)

        text = """
        This vulnerability is tracked as CVE-2021-44228 (Log4Shell).
        Also related to CVE-2021-45046.
        """

        cves = tool._extract_cves(text)

        assert "CVE-2021-44228" in cves
        assert "CVE-2021-45046" in cves
        assert len(cves) == 2


class TestNucleiTool:
    """Tests for NucleiTool wrapper."""

    @pytest.mark.asyncio
    async def test_nuclei_run_success(self, temp_work_dir):
        """Test Nuclei scan with successful execution."""
        tool = NucleiTool(work_dir=temp_work_dir)

        mock_stdout = """
        [INF] Running nuclei scan
        [INF] Targets loaded: 1
        {"template":"http/cves/2021/CVE-2021-44228.yaml","host":"https://example.com","severity":"critical","type":"http"}
        {"template":"http/misconfiguration/apache/apache-default-page.yaml","host":"https://example.com","severity":"info","type":"http"}
        [INF] Scan completed with 2 findings
        """

        async def mock_execute(cmd, timeout=3600):
            return 0, mock_stdout, ""

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("https://example.com", templates="cves")

            assert result.tool_name == "nuclei"
            assert result.target == "https://example.com"
            assert result.success is True
            assert len(result.findings) == 2
            assert any(f["severity"] == "critical" for f in result.findings)

    @pytest.mark.asyncio
    async def test_nuclei_run_with_timeout(self, temp_work_dir):
        """Test Nuclei scan with timeout."""
        tool = NucleiTool(work_dir=temp_work_dir)

        async def mock_execute(cmd, timeout=3600):
            return -1, "", "Command timed out"

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("https://example.com", timeout=300)

            assert result.success is False
            assert result.error is not None

    def test_nuclei_map_severity(self, temp_work_dir):
        """Test Nuclei severity mapping."""
        tool = NucleiTool(work_dir=temp_work_dir)

        assert tool._map_severity("critical") == "critical"
        assert tool._map_severity("high") == "high"
        assert tool._map_severity("medium") == "medium"
        assert tool._map_severity("low") == "low"
        assert tool._map_severity("info") == "info"
        assert tool._map_severity("informational") == "info"
        assert tool._map_severity("unknown") == "info"


class TestSqlmapTool:
    """Tests for SqlmapTool wrapper."""

    @pytest.mark.asyncio
    async def test_sqlmap_run_success(self, temp_work_dir):
        """Test Sqlmap scan with successful execution."""
        tool = SqlmapTool(work_dir=temp_work_dir)

        mock_stdout = """
        ___
        __H__
        ___ ___[)]_____ ___ ___  {1.7.12#stable}
        |_ -| . ["]     | .'| . |
        |___|_  [']_|_|_|__,|  _|
              |_|V...       |_|   https://sqlmap.org

        [INFO] testing connection to target URL
        [INFO] checking if the target is protected by some WAF/IPS
        [INFO] testing if the target URL content is stable
        [INFO] target URL content is stable
        [INFO] heuristic (basic) tests shows that GET parameter 'id' might be injectable
        [INFO] testing for SQL injection on GET parameter 'id'
        [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        [INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable
        [INFO] searching for tables
        Database: webapp
        [Table: users]
        [INFO] fetched data logged to text files
        """

        async def mock_execute(cmd, timeout=3600):
            return 0, mock_stdout, ""

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run(
                "https://example.com/page?id=1",
                level=3,
                risk=2
            )

            assert result.tool_name == "sqlmap"
            assert result.target == "https://example.com/page?id=1"
            assert result.success is True
            assert "sqlmap" in result.raw_output.lower()

    @pytest.mark.asyncio
    async def test_sqlmap_with_waf_detection(self, temp_work_dir):
        """Test Sqlmap with WAF detection."""
        tool = SqlmapTool(work_dir=temp_work_dir)

        mock_stdout = """
        [INFO] testing connection to target URL
        [WARNING] heuristic detection of WAF/IPS/IDS protection
        [WARNING] possible WAF/IPS/IDS detected
        [INFO] trying to bypass WAF/IPS/IDS
        """

        async def mock_execute(cmd, timeout=3600):
            return 0, mock_stdout, ""

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("https://example.com/page?id=1")

            assert result.success is True
            assert "WAF" in result.raw_output
            assert result.metadata.get("waf_detected") is True

    @pytest.mark.asyncio
    async def test_sqlmap_run_failure(self, temp_work_dir):
        """Test Sqlmap scan with failure."""
        tool = SqlmapTool(work_dir=temp_work_dir)

        async def mock_execute(cmd, timeout=3600):
            return 1, "", "[ERROR] unable to connect to target"

        with patch.object(tool, "_execute_command", side_effect=mock_execute):
            result = await tool.run("https://invalid-target")

            assert result.success is False
            assert result.error is not None

    def test_sqlmap_build_command(self, temp_work_dir):
        """Test Sqlmap command building."""
        tool = SqlmapTool(work_dir=temp_work_dir)

        cmd = tool._build_command(
            "https://example.com/page?id=1",
            level=3,
            risk=2,
            dbms="mysql"
        )

        assert "sqlmap" in cmd[0] or cmd[0] == "sqlmap"
        assert "-u" in cmd
        assert "https://example.com/page?id=1" in cmd
        assert "--level" in cmd
        assert "3" in cmd
        assert "--risk" in cmd
        assert "2" in cmd
        assert "--dbms" in cmd
        assert "mysql" in cmd


class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_tool_result_creation(self):
        """Test creating a ToolResult instance."""
        from datetime import datetime, timezone

        result = ToolResult(
            tool_name="test",
            target="example.com",
            success=True,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            raw_output="Test output",
            findings=[{"title": "Test Finding", "severity": "high"}],
        )

        assert result.tool_name == "test"
        assert result.target == "example.com"
        assert result.success is True
        assert len(result.findings) == 1
        assert result.error is None

    def test_tool_result_with_error(self):
        """Test creating a ToolResult with error."""
        from datetime import datetime, timezone

        result = ToolResult(
            tool_name="test",
            target="example.com",
            success=False,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            raw_output="",
            error="Connection failed",
        )

        assert result.success is False
        assert result.error == "Connection failed"


class TestBaseTool:
    """Tests for BaseTool abstract class."""

    def test_base_tool_is_abstract(self):
        """Test that BaseTool is abstract."""
        from netra.scanner.tools.base import BaseTool

        # Should not be able to instantiate BaseTool directly
        with pytest.raises(TypeError):
            BaseTool()

    @pytest.mark.asyncio
    async def test_base_tool_execute_command_not_found(self, temp_work_dir):
        """Test executing a non-existent command."""
        from netra.scanner.tools.base import BaseTool

        class TestTool(BaseTool):
            name = "test"
            binary_name = "nonexistent_binary_xyz"

            async def run(self, target: str, **kwargs):
                return await self._execute_command([self.binary_name, target])

        tool = TestTool(work_dir=temp_work_dir)
        result = await tool.run("example.com")

        assert result[0] == -1  # Return code
        assert "not found" in result[2].lower() or result[0] == -1

    @pytest.mark.asyncio
    async def test_base_tool_execute_command_timeout(self, temp_work_dir):
        """Test command timeout."""
        from netra.scanner.tools.base import BaseTool

        class TestTool(BaseTool):
            name = "test"
            binary_name = "sleep"

            async def run(self, target: str, **kwargs):
                return await self._execute_command(["sleep", "10"], timeout=1)

        tool = TestTool(work_dir=temp_work_dir)
        returncode, stdout, stderr = await tool.run("example.com")

        assert returncode == -1  # Timeout returns -1
        assert "timed out" in stderr.lower()

    def test_base_tool_parse_json_output(self, temp_work_dir):
        """Test parsing JSON output."""
        from netra.scanner.tools.base import BaseTool

        class TestTool(BaseTool):
            name = "test"
            binary_name = "test"

            async def run(self, target: str, **kwargs):
                pass

        tool = TestTool(work_dir=temp_work_dir)

        jsonl_output = """
        {"key": "value1"}
        {"key": "value2"}
        """

        results = tool._parse_json_output(jsonl_output)

        assert len(results) == 2
        assert results[0]["key"] == "value1"
        assert results[1]["key"] == "value2"

    def test_base_tool_map_severity(self, temp_work_dir):
        """Test severity mapping."""
        from netra.scanner.tools.base import BaseTool

        class TestTool(BaseTool):
            name = "test"
            binary_name = "test"

            async def run(self, target: str, **kwargs):
                pass

        tool = TestTool(work_dir=temp_work_dir)

        assert tool._map_severity("CRITICAL") == "critical"
        assert tool._map_severity("High") == "high"
        assert tool._map_severity("MEDIUM") == "medium"
        assert tool._map_severity("Low") == "low"
        assert tool._map_severity("INFO") == "info"
        assert tool._map_severity("Warning") == "medium"
