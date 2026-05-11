"""Trend summaries over the local learning corpus."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup


async def summarize_trends(session: AsyncSession, *, days: int = 7) -> dict[str, Any]:
    """Build a compact week-style summary from corpus rows."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    reports = (
        await session.execute(
            select(BBCorpusReport).where(
                BBCorpusReport.deleted_at.is_(None),
                BBCorpusReport.ingested_at >= since,
            )
        )
    ).scalars().all()
    writeups = (
        await session.execute(
            select(BBCorpusWriteup).where(
                BBCorpusWriteup.deleted_at.is_(None),
                BBCorpusWriteup.ingested_at >= since,
            )
        )
    ).scalars().all()
    advisories = (
        await session.execute(
            select(BBCorpusAdvisory).where(
                BBCorpusAdvisory.deleted_at.is_(None),
                BBCorpusAdvisory.ingested_at >= since,
            )
        )
    ).scalars().all()

    vuln_counter: Counter[str] = Counter()
    tech_counter: Counter[str] = Counter()
    program_counter: Counter[str] = Counter()

    for row in reports:
        if row.vuln_class:
            vuln_counter[str(row.vuln_class)] += 1
        if row.program_handle:
            program_counter[str(row.program_handle)] += 1
        for tech in row.tech_stack or []:
            if str(tech).strip():
                tech_counter[str(tech).strip()] += 1
    for row in writeups:
        if row.vuln_class:
            vuln_counter[str(row.vuln_class)] += 1
        for tech in row.tech_stack or []:
            if str(tech).strip():
                tech_counter[str(tech).strip()] += 1
    for row in advisories:
        for package in row.affected_packages or []:
            if str(package).strip():
                tech_counter[str(package).strip()] += 1

    return {
        "window_days": days,
        "total_reports": len(reports),
        "total_writeups": len(writeups),
        "total_advisories": len(advisories),
        "top_vuln_classes": [{"name": name, "count": count} for name, count in vuln_counter.most_common(5)],
        "top_tech": [{"name": name, "count": count} for name, count in tech_counter.most_common(5)],
        "top_programs": [{"name": name, "count": count} for name, count in program_counter.most_common(5)],
    }
