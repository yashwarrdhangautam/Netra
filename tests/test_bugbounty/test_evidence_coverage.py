"""Coverage tests for the evidence encryptor and the redact-before-store pipeline.

PRD section 9.2 requires that:
    * unredacted bytes are never written to disk,
    * a known AWS-style key is stored as a [REDACTED:...] marker,
    * the encrypted blob round-trips to the redacted content and holds no plaintext,
    * redaction counts are recorded.

Fixtures are obviously fake (AWS documentation example key) and no network is used.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet, InvalidToken

from netra.bugbounty.evidence import encryptor, pipeline
from netra.bugbounty.evidence.encryptor import decrypt, encrypt
from netra.bugbounty.evidence.pipeline import read_evidence_blob, sniff_mime, store_evidence
from netra.db.models.bb_evidence import BBEvidence, BBEvidenceRedaction

AWS_FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL_FAKE = "alice@victim.example.com"


@pytest.fixture
def evidence_root(tmp_path, monkeypatch):
    """Point the pipeline's storage root at a pytest tmp directory."""
    root = tmp_path / "evidence"
    monkeypatch.setattr(pipeline.settings, "evidence_dir", root)
    return root


@pytest.fixture
def fernet_env(monkeypatch):
    """Use an explicit, freshly generated Fernet key (not a secret, generated per run)."""
    monkeypatch.setenv("NETRA_EVIDENCE_KEY", Fernet.generate_key().decode("ascii"))


@pytest.fixture
def session():
    mock = MagicMock()
    mock.flush = AsyncMock()
    return mock


def _added(session, cls):
    return [c.args[0] for c in session.add.call_args_list if isinstance(c.args[0], cls)]


def _all_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


# ── encryptor ───────────────────────────────────────────────────────────────────
class TestEncryptor:
    def test_round_trip_with_explicit_key(self, fernet_env):
        blob = encrypt(b"hello evidence")
        assert decrypt(blob) == b"hello evidence"

    def test_ciphertext_does_not_contain_plaintext(self, fernet_env):
        blob = encrypt(f"header {AWS_FAKE_KEY} trailer".encode())
        assert AWS_FAKE_KEY.encode() not in blob
        assert b"trailer" not in blob

    def test_ciphertext_is_nondeterministic(self, fernet_env):
        # Fernet uses a random IV per token, so identical input yields different blobs.
        assert encrypt(b"same") != encrypt(b"same")

    def test_wrong_key_cannot_decrypt(self, monkeypatch):
        monkeypatch.setenv("NETRA_EVIDENCE_KEY", Fernet.generate_key().decode("ascii"))
        blob = encrypt(b"secret-ish content")
        monkeypatch.setenv("NETRA_EVIDENCE_KEY", Fernet.generate_key().decode("ascii"))
        with pytest.raises(InvalidToken):
            decrypt(blob)

    def test_default_key_is_derived_from_jwt_secret_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("NETRA_EVIDENCE_KEY", raising=False)
        blob = encrypt(b"derived key path")
        expected_key = encryptor.base64.urlsafe_b64encode(
            hashlib.sha256(encryptor.settings.jwt_secret_key.encode("utf-8")).digest()
        )
        assert Fernet(expected_key).decrypt(blob) == b"derived key path"
        assert decrypt(blob) == b"derived key path"

    def test_non_ascii_env_key_is_rejected_not_ignored(self, monkeypatch):
        # Regression for the safety fix: a non-ASCII NETRA_EVIDENCE_KEY must raise,
        # not silently fall back to a key derived from jwt_secret_key.
        monkeypatch.setenv("NETRA_EVIDENCE_KEY", "kéy-not-ascii")
        with pytest.raises(RuntimeError, match="ASCII"):
            encryptor._fernet_key()

    def test_default_jwt_secret_without_evidence_key_fails_closed(self, monkeypatch):
        # Regression for the safety fix: no key + default secret must not produce a key.
        monkeypatch.delenv("NETRA_EVIDENCE_KEY", raising=False)
        monkeypatch.setattr(encryptor.settings, "jwt_secret_key", encryptor.DEFAULT_JWT_SECRET)
        with pytest.raises(RuntimeError, match="refusing"):
            encryptor._fernet_key()

    def test_invalid_fernet_env_key_raises_on_encrypt(self, monkeypatch):
        monkeypatch.setenv("NETRA_EVIDENCE_KEY", "not-a-valid-fernet-key")
        with pytest.raises(ValueError):
            encrypt(b"x")


# ── sniff_mime ──────────────────────────────────────────────────────────────────
class TestSniffMime:
    def test_declared_content_type_wins(self):
        assert sniff_mime("shot.png", "text/plain") == "text/plain"

    def test_guessed_from_filename_when_no_content_type(self):
        assert sniff_mime("notes.txt", None) == "text/plain"

    def test_unknown_extension_falls_back_to_octet_stream(self):
        assert sniff_mime("blob.zzqqx", None) == "application/octet-stream"


# ── store_evidence pipeline ─────────────────────────────────────────────────────
class TestStoreEvidence:
    async def test_aws_key_is_stored_as_redaction_marker(self, evidence_root, fernet_env, session):
        content = f"Response header: X-Key={AWS_FAKE_KEY}\n".encode()
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="resp.txt",
            content=content,
        )
        plain = read_evidence_blob(stored.evidence)
        assert AWS_FAKE_KEY.encode() not in plain
        assert b"[REDACTED:aws_access_key:0]" in plain
        assert [h.rule_id for h in stored.hits] == ["aws_access_key"]

    async def test_no_plaintext_secret_anywhere_under_storage_root(
        self, evidence_root, fernet_env, session
    ):
        content = f"key={AWS_FAKE_KEY} contact={EMAIL_FAKE}".encode()
        await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="dump.txt",
            content=content,
        )
        files = _all_files(evidence_root)
        assert len(files) == 1
        for path in files:
            data = path.read_bytes()
            assert AWS_FAKE_KEY.encode() not in data
            assert EMAIL_FAKE.encode() not in data

    async def test_encrypted_blob_round_trips_to_redacted_content(
        self, evidence_root, fernet_env, session
    ):
        content = f"A={AWS_FAKE_KEY}\nB={EMAIL_FAKE}\n".encode()
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="pair.txt",
            content=content,
        )
        on_disk = Path(stored.evidence.storage_path).read_bytes()
        assert AWS_FAKE_KEY.encode() not in on_disk
        assert EMAIL_FAKE.encode() not in on_disk
        recovered = decrypt(on_disk)
        assert recovered == b"A=[REDACTED:aws_access_key:0]\nB=[REDACTED:email:0]\n"

    async def test_redaction_count_and_rows_recorded(self, evidence_root, fernet_env, session):
        content = f"{AWS_FAKE_KEY} and {EMAIL_FAKE}".encode()
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="x.txt",
            content=content,
        )
        assert stored.evidence.redaction_count == 2
        rows = _added(session, BBEvidenceRedaction)
        assert {r.rule_id for r in rows} == {"aws_access_key", "email"}
        assert all(r.evidence_id == stored.evidence.id for r in rows)

    async def test_sha256_and_size_describe_redacted_bytes(
        self, evidence_root, fernet_env, session
    ):
        content = f"k={AWS_FAKE_KEY}".encode()
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="x.txt",
            content=content,
        )
        redacted = b"k=[REDACTED:aws_access_key:0]"
        assert stored.evidence.sha256 == hashlib.sha256(redacted).hexdigest()
        assert stored.evidence.size_bytes == len(redacted)
        assert stored.evidence.encrypted is True

    async def test_clean_content_has_zero_redactions(self, evidence_root, fernet_env, session):
        content = b"plain incident notes, nothing sensitive"
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="clean.txt",
            content=content,
        )
        assert stored.hits == []
        assert stored.evidence.redaction_count == 0
        assert _added(session, BBEvidenceRedaction) == []
        assert read_evidence_blob(stored.evidence) == content

    async def test_storage_layout_is_program_finding_uuid_enc(
        self, evidence_root, fernet_env, session
    ):
        program_id, finding_id = uuid.uuid4(), uuid.uuid4()
        stored = await store_evidence(
            session,
            finding_id=finding_id,
            program_id=program_id,
            filename="x.txt",
            content=b"abc",
        )
        path = Path(stored.evidence.storage_path)
        assert path.parent == evidence_root / str(program_id) / str(finding_id)
        assert path.name == f"{stored.evidence.id}.enc"
        assert path.exists()

    async def test_filename_is_reduced_to_basename(self, evidence_root, fernet_env, session):
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="../../etc/passwd.txt",
            content=b"abc",
        )
        assert stored.evidence.filename == "passwd.txt"

    async def test_empty_filename_defaults_to_evidence_txt(
        self, evidence_root, fernet_env, session
    ):
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="",
            content=b"abc",
        )
        assert stored.evidence.filename == "evidence.txt"
        assert stored.evidence.mime_type == "text/plain"

    async def test_metadata_defaults_to_empty_dict(self, evidence_root, fernet_env, session):
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="x.txt",
            content=b"abc",
        )
        assert stored.evidence.metadata_ == {}

    async def test_invalid_utf8_input_is_stored_and_redacted(
        self, evidence_root, fernet_env, session
    ):
        content = b"\xff\xfe " + AWS_FAKE_KEY.encode() + b" \xc3\x28"
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="bin.dat",
            content=content,
        )
        plain = read_evidence_blob(stored.evidence)
        assert AWS_FAKE_KEY.encode() not in plain
        assert stored.evidence.redaction_count == 1


class TestReadEvidenceBlob:
    def test_unencrypted_row_returns_raw_bytes(self, tmp_path):
        path = tmp_path / "raw.bin"
        path.write_bytes(b"raw bytes")
        row = BBEvidence(
            id=uuid.uuid4(),
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="raw.bin",
            mime_type="application/octet-stream",
            storage_path=str(path),
            sha256="0" * 64,
            encrypted=False,
        )
        assert read_evidence_blob(row) == b"raw bytes"


# ── SAFETY findings (documented current behaviour, source not modified) ─────────
class TestUnredactedFieldsReachDatabase:
    """SAFETY: the PRD requires redact-before-store, but only `content` is redacted.

    `filename` (pipeline.py:47,60) and caller-supplied `metadata` (pipeline.py:67)
    are persisted to the bb_evidence row verbatim. These tests pin the current
    behaviour so a future fix flips them deliberately. If they start failing because
    the values are redacted, update the assertions to the new contract.
    """

    async def test_filename_with_aws_key_is_stored_verbatim(
        self, evidence_root, fernet_env, session
    ):
        # Regression for the safety fix: pipeline.py redacts the filename before the DB row.
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename=f"{AWS_FAKE_KEY}.txt",
            content=b"abc",
        )
        assert AWS_FAKE_KEY not in stored.evidence.filename
        assert "[REDACTED:" in stored.evidence.filename

    async def test_metadata_with_aws_key_is_stored_verbatim(
        self, evidence_root, fernet_env, session
    ):
        # Regression for the safety fix: caller metadata is redacted before it is persisted.
        stored = await store_evidence(
            session,
            finding_id=uuid.uuid4(),
            program_id=uuid.uuid4(),
            filename="x.txt",
            content=b"abc",
            metadata={"note": f"key was {AWS_FAKE_KEY}"},
        )
        assert AWS_FAKE_KEY not in str(stored.evidence.metadata_)
        assert "[REDACTED:" in str(stored.evidence.metadata_)
