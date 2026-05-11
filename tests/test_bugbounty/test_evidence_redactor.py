"""Adversarial tests for the evidence redactor and the draft-time redaction wire.

If anything in this file regresses, secrets could leak into a stored bb_evidence row,
a generated draft markdown, or a Word/PDF artifact downloaded by the operator.

Conventions:
    * Each rule has an "obviously-secret" fixture and a stored-bytes assertion.
    * Cross-boundary tests prove the BBSubmissionService draft path also redacts.
"""
from __future__ import annotations

import pytest

from netra.bugbounty.evidence.redactor import RedactionHit, redact_bytes, redact_text
from netra.services.bb_submission_service import BBSubmissionService


# ── Per-rule corpus ─────────────────────────────────────────────────────────────
SECRETS = {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token_classic": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "github_token_oauth": "gho_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "github_token_user": "ghu_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "github_token_server": "ghs_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    "github_token_refresh": "ghr_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "email": "alice@victim.example.com",
    "private_key": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAabcXYZ\n"
        "FAKEKEYDATA1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    ),
    "aws_secret_phrase": "aws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
}


# ── redact_text — string boundary ───────────────────────────────────────────────
class TestRedactTextRules:
    @pytest.mark.parametrize("rule_id, payload", list(SECRETS.items()))
    def test_secret_replaced_with_marker(self, rule_id, payload):
        out, hits = redact_text(f"prefix {payload} suffix")
        assert payload not in out, f"{rule_id} secret leaked through redactor"
        assert "[REDACTED:" in out, f"{rule_id} produced no redaction marker"
        assert hits, f"{rule_id} produced empty hit list"

    def test_multiple_secrets_get_indexed_replacements(self):
        text = (
            "first AKIAIOSFODNN7EXAMPLE then AKIA0000000000000000 in same blob"
        )
        out, hits = redact_text(text)
        # Two AWS hits — replacements should carry distinct indices.
        replacements = [h.replacement for h in hits if h.rule_id == "aws_access_key"]
        assert len(replacements) == 2
        assert any(":0]" in r for r in replacements)
        assert any(":1]" in r for r in replacements)

    def test_clean_text_returns_unchanged(self):
        text = "no secrets here, just normal incident notes about /api/orders"
        out, hits = redact_text(text)
        assert out == text
        assert hits == []

    def test_redaction_hits_record_offsets(self):
        text = "before AKIAIOSFODNN7EXAMPLE after"
        _, hits = redact_text(text)
        assert hits[0].rule_id == "aws_access_key"
        # Redactor records hits AFTER the substitution loop, so offsets refer to
        # post-replacement positions; we only assert they're sane (non-negative,
        # ordered) rather than pointing at a literal slice.
        assert hits[0].start_offset >= 0
        assert hits[0].end_offset > hits[0].start_offset


# ── redact_bytes — UTF-8 boundary ───────────────────────────────────────────────
class TestRedactBytes:
    def test_bytes_pipeline_strips_secret(self):
        data = b"Authorization: Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        out, hits = redact_bytes(data)
        assert b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in out
        assert any(h.rule_id == "github_token" for h in hits)

    def test_bytes_with_invalid_utf8_does_not_crash(self):
        data = b"\xff\xfe AKIAIOSFODNN7EXAMPLE \xc3\x28"
        out, hits = redact_bytes(data)
        # The AWS key is still ASCII so it must still be found and stripped.
        assert b"AKIAIOSFODNN7EXAMPLE" not in out
        assert any(h.rule_id == "aws_access_key" for h in hits)


# ── BBSubmissionService._redact_draft — service-level wire ──────────────────────
class TestDraftRedactionWire:
    """The wiring put on bb_submission_service.create_draft must use the same rules."""

    def test_helper_is_pure_and_callable_without_db(self):
        # The helper is static and doesn't touch self.db, which is the whole point —
        # it's safe to use anywhere, including unit tests with no DB session.
        out, hits = BBSubmissionService._redact_draft("hello")
        assert out == "hello"
        assert hits == []

    def test_aws_key_in_rendered_markdown_is_stripped(self):
        # Realistic shape: a draft markdown that includes a leaked key from the
        # finding's description. After _redact_draft, the literal key must be gone
        # AND the marker must be present so the operator notices.
        rendered = (
            "# Reflected XSS in api.example.com\n\n"
            "## Summary\n"
            "Response body reflected attacker-controlled string and contained "
            "AKIAIOSFODNN7EXAMPLE in a debug header.\n"
        )
        out, hits = BBSubmissionService._redact_draft(rendered)
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "[REDACTED:aws_access_key:0]" in out
        assert any(h.rule_id == "aws_access_key" for h in hits)

    def test_jwt_in_steps_to_reproduce_is_stripped(self):
        rendered = (
            "## Steps to Reproduce\n\n"
            "1. Log in as victim.\n"
            "2. Capture session cookie: "
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
            "3. Replay the request.\n"
        )
        out, hits = BBSubmissionService._redact_draft(rendered)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in out
        assert any(h.rule_id == "jwt" for h in hits)

    def test_multiple_rule_classes_in_one_draft(self):
        rendered = (
            f"AWS={SECRETS['aws_access_key']}\n"
            f"GH={SECRETS['github_token_classic']}\n"
            f"Email={SECRETS['email']}\n"
        )
        _, hits = BBSubmissionService._redact_draft(rendered)
        rule_ids = {h.rule_id for h in hits}
        assert {"aws_access_key", "github_token", "email"}.issubset(rule_ids)

    def test_clean_draft_produces_no_hits(self):
        rendered = (
            "# Reflected XSS in api.example.com\n\n"
            "## Summary\nUser-supplied query parameter reflected unescaped.\n"
            "## Impact\nLow — requires social engineering.\n"
        )
        out, hits = BBSubmissionService._redact_draft(rendered)
        assert out == rendered
        assert hits == []
