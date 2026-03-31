"""Tests for AI Brain consensus logic."""
import pytest
from unittest.mock import AsyncMock, patch

from netra.ai.brain import AIBrain
from netra.db.models.finding import Finding, FindingSeverity


@pytest.fixture
def ai_brain():
    """Create an AI Brain instance with provider set to 'none'."""
    with patch("netra.ai.brain.settings") as mock_settings:
        mock_settings.ai_provider = "none"
        brain = AIBrain()
        yield brain


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        title="SQL Injection Vulnerability",
        severity=FindingSeverity.CRITICAL,
        url="https://example.com/login",
        parameter="username",
        cwe_id="CWE-89",
        cve_ids=["CVE-2024-1234"],
        tool_source="sqlmap",
        description="SQL injection vulnerability detected in login form",
        evidence={"payload": "' OR '1'='1", "response": "Database error"},
        confidence=80,
    )


class TestAIBrainAnalyzeFinding:
    """Tests for AIBrain.analyze_finding method."""

    @pytest.mark.asyncio
    async def test_analyze_finding_with_provider_none(self, ai_brain, sample_finding):
        """Test analysis when AI provider is 'none'."""
        result = await ai_brain.analyze_finding(sample_finding)

        assert result["attacker"] == {}
        assert result["defender"] == {}
        assert result["analyst"] == {}
        assert result["skeptic"] == {}
        assert result["confidence"] == sample_finding.confidence
        assert "consensus" not in result or result.get("consensus") is None

    @pytest.mark.asyncio
    async def test_analyze_finding_with_anthropic(self, sample_finding):
        """Test analysis with Anthropic provider."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "anthropic"
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.anthropic_model = "claude-sonnet-4-20250514"
            mock_settings.anthropic_skeptic_model = "claude-haiku-3-5"

            brain = AIBrain()

            # Mock the _query_persona method to return test responses
            async def mock_query_persona(name, prompt, context):
                responses = {
                    "attacker": {
                        "exploitability": "high",
                        "attack_chain": ["recon", "exploit", "exfiltrate"],
                        "confidence": 85,
                    },
                    "defender": {
                        "remediation": "Use parameterized queries",
                        "effort": "medium",
                        "confidence": 90,
                    },
                    "analyst": {
                        "compliance_mappings": ["PCI-DSS 6.5.1", "OWASP A03:2021"],
                        "cwe_details": "SQL Injection",
                        "confidence": 95,
                    },
                    "skeptic": {
                        "verdict": "confirmed",
                        "evidence_quality": "high",
                        "confidence": 80,
                    },
                }
                return responses.get(name, {})

            with patch.object(brain, "_query_persona", side_effect=mock_query_persona):
                result = await brain.analyze_finding(sample_finding)

                assert result["attacker"]["exploitability"] == "high"
                assert result["defender"]["remediation"] == "Use parameterized queries"
                assert result["analyst"]["compliance_mappings"] == [
                    "PCI-DSS 6.5.1",
                    "OWASP A03:2021",
                ]
                assert result["skeptic"]["verdict"] == "confirmed"
                assert "consensus" in result
                assert result["consensus"]["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_analyze_finding_with_ollama(self, sample_finding):
        """Test analysis with Ollama provider."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "ollama"
            mock_settings.ollama_base_url = "http://localhost:11434"
            mock_settings.ollama_model = "llama3.1:8b"

            brain = AIBrain()

            async def mock_query_persona(name, prompt, context):
                return {
                    "confidence": 75,
                    "verdict": "confirmed" if name != "skeptic" else "confirmed",
                }

            with patch.object(brain, "_query_persona", side_effect=mock_query_persona):
                result = await brain.analyze_finding(sample_finding)

                assert "consensus" in result
                assert result["consensus"]["status"] == "confirmed"


class TestComputeConsensus:
    """Tests for AIBrain._compute_consensus method."""

    @pytest.fixture
    def brain(self):
        """Create AI Brain for consensus tests."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "none"
            return AIBrain()

    def test_consensus_all_confirmed(self, brain):
        """Test consensus when all personas confirm."""
        results = {
            "attacker": {"confidence": 85},
            "defender": {"confidence": 90},
            "analyst": {"confidence": 80},
            "skeptic": {"confidence": 75, "verdict": "confirmed"},
        }

        consensus = brain._compute_consensus(results)

        assert consensus["status"] == "confirmed"
        assert consensus["final_confidence"] >= 70
        assert "persona_confidences" in consensus

    def test_consensus_skeptic_false_positive(self, brain):
        """Test consensus when skeptic says false positive."""
        results = {
            "attacker": {"confidence": 85},
            "defender": {"confidence": 90},
            "analyst": {"confidence": 80},
            "skeptic": {"confidence": 75, "verdict": "false_positive"},
        }

        consensus = brain._compute_consensus(results)

        assert consensus["status"] == "false_positive"
        assert consensus["final_confidence"] == 10
        assert "false positive" in consensus["reasoning"].lower()

    def test_consensus_skeptic_likely_fp(self, brain):
        """Test consensus when skeptic says likely false positive."""
        results = {
            "attacker": {"confidence": 85},
            "defender": {"confidence": 90},
            "analyst": {"confidence": 80},
            "skeptic": {"confidence": 75, "verdict": "likely_false_positive"},
        }

        consensus = brain._compute_consensus(results)

        assert consensus["status"] == "needs_review"
        assert consensus["final_confidence"] <= 30

    def test_consensus_skeptic_needs_evidence(self, brain):
        """Test consensus when skeptic needs more evidence."""
        results = {
            "attacker": {"confidence": 85},
            "defender": {"confidence": 90},
            "analyst": {"confidence": 80},
            "skeptic": {"confidence": 75, "verdict": "needs_evidence"},
        }

        consensus = brain._compute_consensus(results)

        assert consensus["status"] == "needs_evidence"
        assert consensus["final_confidence"] <= 60

    def test_consensus_low_confidence(self, brain):
        """Test consensus with low confidence scores."""
        results = {
            "attacker": {"confidence": 40},
            "defender": {"confidence": 50},
            "analyst": {"confidence": 45},
            "skeptic": {"confidence": 55, "verdict": "confirmed"},
        }

        consensus = brain._compute_consensus(results)

        assert consensus["status"] == "needs_review"
        assert consensus["final_confidence"] < 70


class TestFindingToContext:
    """Tests for AIBrain._finding_to_context method."""

    @pytest.fixture
    def brain(self):
        """Create AI Brain for context tests."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "none"
            return AIBrain()

    def test_finding_to_context_basic(self, brain, sample_finding):
        """Test converting finding to context string."""
        context = brain._finding_to_context(sample_finding)

        assert "SQL Injection Vulnerability" in context
        assert "critical" in context.lower()
        assert "https://example.com/login" in context
        assert "username" in context
        assert "CWE-89" in context
        assert "CVE-2024-1234" in context
        assert "sqlmap" in context
        assert "Database error" in context

    def test_finding_to_context_missing_fields(self, brain):
        """Test converting finding with missing fields."""
        finding = Finding(
            title="Test Finding",
            severity=FindingSeverity.LOW,
            url=None,
            parameter=None,
            cwe_id=None,
            cve_ids=[],
            tool_source="test",
            description="Test description",
            evidence={},
            confidence=50,
        )

        context = brain._finding_to_context(finding)

        assert "N/A" in context  # Missing fields should show N/A
        assert "Test Finding" in context


class TestParseAiJson:
    """Tests for AIBrain._parse_ai_json method."""

    @pytest.fixture
    def brain(self):
        """Create AI Brain for JSON parsing tests."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "none"
            return AIBrain()

    def test_parse_clean_json(self, brain):
        """Test parsing clean JSON."""
        json_str = '{"key": "value", "number": 42}'
        result = brain._parse_ai_json(json_str)

        assert result["key"] == "value"
        assert result["number"] == 42

    def test_parse_json_with_markdown(self, brain):
        """Test parsing JSON wrapped in markdown code blocks."""
        json_str = '```json\n{"key": "value"}\n```'
        result = brain._parse_ai_json(json_str)

        assert result["key"] == "value"

    def test_parse_json_with_generic_markdown(self, brain):
        """Test parsing JSON with generic markdown block."""
        json_str = '```\n{"key": "value"}\n```'
        result = brain._parse_ai_json(json_str)

        assert result["key"] == "value"

    def test_parse_invalid_json(self, brain, caplog):
        """Test parsing invalid JSON."""
        json_str = '{"invalid": json}'
        result = brain._parse_ai_json(json_str)

        assert "raw_response" in result
        assert "ai_json_parse_failed" in caplog.text


class TestDiscoverAttackChains:
    """Tests for AIBrain.discover_attack_chains method."""

    @pytest.mark.asyncio
    async def test_discover_attack_chains_few_findings(self):
        """Test attack chain discovery with insufficient findings."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "none"
            brain = AIBrain()

            findings = [
                Finding(
                    title="Single Finding",
                    severity=FindingSeverity.LOW,
                    tool_source="test",
                    description="Test",
                    confidence=50,
                )
            ]

            result = await brain.discover_attack_chains(findings)
            assert result == []

    @pytest.mark.asyncio
    async def test_discover_attack_chains_with_anthropic(self):
        """Test attack chain discovery with Anthropic."""
        with patch("netra.ai.brain.settings") as mock_settings:
            mock_settings.ai_provider = "anthropic"
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.anthropic_model = "claude-sonnet-4-20250514"

            brain = AIBrain()

            findings = [
                Finding(
                    title="SQL Injection",
                    severity=FindingSeverity.CRITICAL,
                    url="https://example.com/login",
                    cwe_id="CWE-89",
                    tool_source="sqlmap",
                    description="SQL injection",
                    confidence=80,
                ),
                Finding(
                    title="XSS Vulnerability",
                    severity=FindingSeverity.HIGH,
                    url="https://example.com/search",
                    cwe_id="CWE-79",
                    tool_source="dalfox",
                    description="XSS vulnerability",
                    confidence=75,
                ),
            ]

            # Mock the _query_persona method
            async def mock_query_persona(name, prompt, context):
                return {
                    "attack_chains": [
                        {
                            "name": "SQLi to XSS Chain",
                            "description": "Combine SQLi and XSS for data theft",
                            "steps": ["SQLi to extract sessions", "XSS to hijack"],
                            "combined_cvss": 9.8,
                        }
                    ]
                }

            with patch.object(brain, "_query_persona", side_effect=mock_query_persona):
                result = await brain.discover_attack_chains(findings)

                assert len(result) > 0
                assert "attack_chains" in result[0] if result else True
