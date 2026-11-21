"""Profile configuration, source containment and credential-write boundaries."""

import pytest
from sqlalchemy import insert, update

from netra.db.models.credential import Credential
from netra.schemas.scan_config import validate_scan_config
from netra.services.source_paths import resolve_source_path


@pytest.mark.parametrize(
    "config",
    [
        {"token": "secret"},
        {"rate_limit": True},
        {"rate_limit": {"nested": "secret"}},
        {"url": "https://u:p@example.org"},
        {"unknown": 1},
    ],
)
def test_invalid_config_is_rejected(config):
    with pytest.raises(ValueError):
        validate_scan_config("quick", config)


def test_profile_config_types_and_keys():
    assert validate_scan_config("quick", {"rate_limit": 2, "test_sqli": False}) == {
        "rate_limit": 2,
        "test_sqli": False,
    }
    with pytest.raises(ValueError):
        validate_scan_config("quick", {"source_path": "repo"})
    assert validate_scan_config("bugbounty_active", {"enable_nuclei": False, "agentic": True})


def test_source_path_stays_inside_root(tmp_path):
    root = tmp_path / "sources"
    root.mkdir()
    inside = root / "repo"
    inside.mkdir()
    assert resolve_source_path("repo", base_dir=root) == inside.resolve()
    with pytest.raises(ValueError):
        resolve_source_path("../outside", base_dir=root)
    with pytest.raises(ValueError):
        resolve_source_path(tmp_path, base_dir=root)


def test_source_symlink_escape_is_denied(tmp_path):
    root = tmp_path / "sources"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not permit symlink creation")
    with pytest.raises(ValueError):
        resolve_source_path(link, base_dir=root)


async def test_plaintext_credential_orm_insert_is_denied(db_session):
    db_session.add(Credential(name="blocked", credential_type="token", token="synthetic"))
    with pytest.raises(ValueError, match="credential_storage_unavailable"):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.parametrize(
    "statement",
    [
        insert(Credential).values(name="blocked", credential_type="token", token="synthetic"),
        update(Credential).values(token="synthetic"),
    ],
)
async def test_plaintext_credential_bulk_write_is_denied(db_session, statement):
    with pytest.raises(ValueError, match="credential_storage_unavailable"):
        await db_session.execute(statement)


async def test_plaintext_credential_core_write_is_denied(db_session):
    connection = await db_session.connection()
    with pytest.raises(ValueError, match="credential_storage_unavailable"):
        await connection.execute(
            insert(Credential.__table__).values(
                name="blocked", credential_type="token", token="synthetic"
            )
        )
