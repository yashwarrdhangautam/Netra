"""Scan service for business logic."""
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.scan import Scan, ScanProfile
from netra.db.models.target import Target, TargetType
from netra.worker.tasks import run_bugbounty_scan


class ScanService:
    """Service for scan-related business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize scan service.

        Args:
            db: Async database session
        """
        self.db = db

    # Phase 1: implement real service methods
    async def create_bugbounty_scan(
        self,
        *,
        program,
        profile: str,
        enable_nuclei: bool = False,
        enable_ffuf: bool = False,
        agentic: bool = False,
        dry_run: bool = False,
        enqueue: bool = True,
    ) -> Scan:
        """Create and optionally enqueue a NETRA-BB scan."""
        target = Target(
            name=f"bb:{program.handle}",
            target_type=TargetType.DOMAIN,
            value=program.handle,
            metadata_={"program_id": str(program.id), "platform": str(program.platform)},
        )
        self.db.add(target)
        await self.db.flush()

        scan = Scan(
            name=f"Bug bounty {profile} hunt: {program.handle}",
            profile=ScanProfile.BUGBOUNTY_ACTIVE if profile == "active" else ScanProfile.BUGBOUNTY_PASSIVE,
            target_id=target.id,
            config={
                "program_id": str(program.id),
                "program_handle": program.handle,
                "platform": str(program.platform),
                "enable_nuclei": enable_nuclei,
                "enable_ffuf": enable_ffuf,
                "agentic": agentic,
                "dry_run": dry_run,
            },
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        if enqueue:
            task = run_bugbounty_scan.delay(str(scan.id))
            scan.config = {
                **(scan.config or {}),
                "celery_task_id": task.id,
            }
            await self.db.commit()
            await self.db.refresh(scan)
        return scan
