"""Public signature and inventory sources: chaos program index, nuclei-templates, Wappalyzer.

What each source stores (see ``BBCorpusSignature``):

- ``chaos``: one row per bounty program in ProjectDiscovery's public chaos index
  (name, platform, asset count, last update). This is an inventory, not asset data.
- ``nuclei-templates`` and ``wappalyzer``: one ``head`` row each with the upstream
  commit SHA and date. The doctor check uses it to show how stale the local copy is.
  Template and fingerprint bodies are not imported here yet.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.fetcher import LearningFetcher
from netra.bugbounty.learning.ingest import log_ingest
from netra.core.config import settings
from netra.db.models.bb_corpus_signature import BBCorpusSignature

CHAOS_INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"
GITHUB_COMMIT_URL = "https://api.github.com/repos/{repo}/commits/{branch}"

REPO_SOURCES: dict[str, str] = {
    "projectdiscovery/nuclei-templates": "nuclei-templates",
    "enthec/webappanalyzer": "wappalyzer",
}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def parse_chaos_index(payload: Any) -> list[dict[str, Any]]:
    """Keep only well-formed entries; ignore anything else in the feed."""
    if not isinstance(payload, list):
        return []
    rows: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        rows.append(
            {
                "name": entry["name"].strip()[:255],
                "platform": str(entry.get("platform") or "")[:60],
                "program_url": str(entry.get("program_url") or "")[:500],
                "count": int(entry.get("count") or 0),
                "bounty": bool(entry.get("bounty")),
                "last_updated": _parse_time(entry.get("last_updated")),
            }
        )
    return rows


def parse_commit_head(payload: Any) -> dict[str, Any] | None:
    """Return the SHA and committed date from a GitHub commit response."""
    if not isinstance(payload, dict) or not isinstance(payload.get("sha"), str):
        return None
    committed = (payload.get("commit") or {}).get("committer", {}).get("date")
    return {"sha": payload["sha"], "committed_at": _parse_time(committed)}


async def _upsert_signature(
    session: AsyncSession,
    *,
    source_repo: str,
    tag: str,
    blob: str,
    metadata: dict[str, Any],
    updated_at: datetime | None,
    now: datetime,
) -> bool:
    """Insert or update one signature row. Returns True when a row was created."""
    row = (
        await session.execute(
            select(BBCorpusSignature).where(
                BBCorpusSignature.source_repo == source_repo,
                BBCorpusSignature.tag == tag,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        session.add(
            BBCorpusSignature(
                source_repo=source_repo,
                tag=tag,
                signature_blob=blob,
                metadata_=metadata,
                updated_at_source=updated_at,
            )
        )
        return True
    row.signature_blob = blob
    row.metadata_ = metadata
    row.updated_at_source = updated_at
    row.deleted_at = None
    return False


async def ingest_chaos_index(
    session: AsyncSession,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, int]:
    started = datetime.now(UTC)
    if not settings.corpus_source_chaos:
        await log_ingest(
            session,
            source_name="chaos_index",
            items_added=0,
            items_updated=0,
            notes="disabled_by_config",
            started_at=started,
        )
        await session.commit()
        return {"added": 0, "updated": 0}

    fetcher = LearningFetcher(client=client)
    rows = parse_chaos_index(await fetcher.get_json(CHAOS_INDEX_URL))
    added = updated = 0
    for row in rows:
        created = await _upsert_signature(
            session,
            source_repo="chaos",
            tag=row["name"],
            blob=json.dumps(row, default=str, sort_keys=True),
            metadata={"platform": row["platform"], "program_url": row["program_url"]},
            updated_at=row["last_updated"],
            now=started,
        )
        added += int(created)
        updated += int(not created)
    await log_ingest(
        session,
        source_name="chaos_index",
        items_added=added,
        items_updated=updated,
        started_at=started,
    )
    await session.commit()
    return {"added": added, "updated": updated}


async def ingest_repo_heads(
    session: AsyncSession,
    *,
    client: httpx.AsyncClient | None = None,
    branch: str = "main",
) -> dict[str, int]:
    started = datetime.now(UTC)
    fetcher = LearningFetcher(client=client)
    added = updated = 0
    errors: list[str] = []
    for repo, source in REPO_SOURCES.items():
        try:
            head = parse_commit_head(
                await fetcher.get_json(GITHUB_COMMIT_URL.format(repo=repo, branch=branch))
            )
        except Exception as exc:  # noqa: BLE001 - one repo failing must not stop the other
            errors.append(f"{repo}: {exc}")
            continue
        if head is None:
            errors.append(f"{repo}: unexpected response")
            continue
        created = await _upsert_signature(
            session,
            source_repo=source,
            tag="head",
            blob=head["sha"],
            metadata={"repo": repo, "branch": branch},
            updated_at=head["committed_at"],
            now=started,
        )
        added += int(created)
        updated += int(not created)
    await log_ingest(
        session,
        source_name="repo_heads",
        items_added=added,
        items_updated=updated,
        errors=errors or None,
        started_at=started,
    )
    await session.commit()
    return {"added": added, "updated": updated, "errors": len(errors)}
