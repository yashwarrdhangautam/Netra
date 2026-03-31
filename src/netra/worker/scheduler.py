"""Scan scheduling with Celery Beat for recurring scans.

Supports:
- Cron-based scheduling
- Interval-based scheduling
- One-time scheduled scans
- Schedule management API
"""
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from celery.schedules import crontab
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base
from netra.worker.celery_app import celery_app

logger = structlog.get_logger()


# ── Database Models ──────────────────────────────────────────────────────────


class ScheduleType(str):
    """Schedule type enumeration."""
    CRON = "cron"
    INTERVAL = "interval"
    ONCE = "once"


class ScanSchedule(Base):
    """Model for storing recurring scan schedules."""

    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Target reference
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id"), nullable=False
    )

    # Schedule configuration
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Cron fields (for CRON type)
    cron_minute: Mapped[str | None] = mapped_column(String(100))  # e.g., "0", "*/15", "0 30"
    cron_hour: Mapped[str | None] = mapped_column(String(100))  # e.g., "*", "9-17", "2"
    cron_day_of_week: Mapped[str | None] = mapped_column(String(100))  # e.g., "*", "mon-fri"
    cron_day_of_month: Mapped[str | None] = mapped_column(String(100))  # e.g., "*", "1,15"
    cron_month_of_year: Mapped[str | None] = mapped_column(String(100))  # e.g., "*", "jan,jul"

    # Interval fields (for INTERVAL type)
    interval_seconds: Mapped[int | None] = mapped_column(Integer)

    # One-time schedule (for ONCE type)
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Scan configuration
    profile: Mapped[str] = mapped_column(String(50), default="standard")
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    failed_runs: Mapped[int] = mapped_column(Integer, default=0)

    # Notifications
    notify_on_complete: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_failure: Mapped[bool] = mapped_column(Boolean, default=True)
    notification_emails: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Metadata
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def get_crontab(self) -> crontab | None:
        """Get Celery crontab object for this schedule.

        Returns:
            Crontab object or None if not a cron schedule
        """
        if self.schedule_type != "cron":
            return None

        return crontab(
            minute=self.cron_minute or "*",
            hour=self.cron_hour or "*",
            day_of_week=self.cron_day_of_week or "*",
            day_of_month=self.cron_day_of_month or "*",
            month_of_year=self.cron_month_of_year or "*",
        )

    def get_next_run(self) -> datetime:
        """Calculate next run time based on schedule type.

        Returns:
            Next scheduled run datetime
        """
        now = datetime.now(UTC)

        if self.schedule_type == "once":
            return self.scheduled_at

        elif self.schedule_type == "interval":
            if self.last_run_at:
                return self.last_run_at + timedelta(seconds=self.interval_seconds)
            return now + timedelta(seconds=self.interval_seconds)

        elif self.schedule_type == "cron":
            # Simple approximation - in production, use proper cron calculation
            crontab_obj = self.get_crontab()
            if crontab_obj:
                # Get next matching time
                return now + timedelta(hours=1)  # Simplified

        return now


# ── Celery Tasks for Scheduling ──────────────────────────────────────────────


@celery_app.task(bind=True, name="netra.scheduled_scan")
def execute_scheduled_scan(
    self,
    schedule_id: str,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Execute a scheduled scan.

    Args:
        schedule_id: Schedule UUID as string
        scan_id: Optional existing scan ID

    Returns:
        Task result dictionary
    """
    import asyncio

    from sqlalchemy import select

    from netra.db.models.scan import Scan
    from netra.db.models.target import Target
    from netra.db.session import AsyncSessionLocal

    schedule_uuid = uuid.UUID(schedule_id)
    db = AsyncSessionLocal()

    try:
        # Get schedule
        result = asyncio.run(db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_uuid)
        ))
        schedule = result.scalar_one_or_none()

        if not schedule:
            logger.error("schedule_not_found", schedule_id=schedule_id)
            return {"status": "error", "message": "Schedule not found"}

        if not schedule.is_active:
            logger.info("schedule_inactive", schedule_id=schedule_id)
            return {"status": "skipped", "message": "Schedule is inactive"}

        # Get target
        target_result = asyncio.run(db.execute(
            select(Target).where(Target.id == schedule.target_id)
        ))
        target = target_result.scalar_one_or_none()

        if not target:
            logger.error("target_not_found", target_id=str(schedule.target_id))
            return {"status": "error", "message": "Target not found"}

        # Create new scan
        scan = Scan(
            name=f"{schedule.name} - {datetime.now(UTC).isoformat()}",
            target_id=schedule.target_id,
            profile=schedule.profile,
            config=schedule.config,
            status="pending",
        )
        db.add(scan)
        asyncio.run(db.commit())
        asyncio.run(db.refresh(scan))

        logger.info(
            "scheduled_scan_created",
            schedule_id=schedule_id,
            scan_id=str(scan.id),
        )

        # Trigger scan execution via Celery
        from netra.worker.tasks import run_scan
        run_scan.delay(str(scan.id))

        # Update schedule metadata
        schedule.last_run_at = datetime.now(UTC)
        schedule.total_runs += 1
        schedule.next_run_at = schedule.get_next_run()
        asyncio.run(db.commit())

        return {
            "status": "success",
            "schedule_id": schedule_id,
            "scan_id": str(scan.id),
        }

    except Exception as e:
        logger.error(
            "scheduled_scan_failed",
            schedule_id=schedule_id,
            error=str(e),
        )

        # Update failed runs counter
        try:
            schedule.failed_runs += 1
            asyncio.run(db.commit())
        except Exception:
            pass

        return {"status": "error", "message": str(e)}

    finally:
        asyncio.run(db.close())


@celery_app.task(bind=True, name="netra.cleanup_old_schedules")
def cleanup_old_schedules(self) -> dict[str, Any]:
    """Cleanup old one-time schedules that have already run.

    Returns:
        Task result dictionary
    """
    import asyncio

    from sqlalchemy import select

    from netra.db.session import AsyncSessionLocal

    db = AsyncSessionLocal()
    now = datetime.now(UTC)

    try:
        # Find old one-time schedules
        result = asyncio.run(db.execute(
            select(ScanSchedule).where(
                ScanSchedule.schedule_type == "once",
                ScanSchedule.scheduled_at < now - timedelta(days=7),
                ScanSchedule.is_active is True,
            )
        ))
        old_schedules = result.scalars().all()

        # Deactivate old schedules
        for schedule in old_schedules:
            schedule.is_active = False

        asyncio.run(db.commit())

        logger.info(
            "cleanup_old_schedules",
            deactivated=len(old_schedules),
        )

        return {
            "status": "success",
            "deactivated_count": len(old_schedules),
        }

    except Exception as e:
        logger.error("cleanup_schedules_failed", error=str(e))
        return {"status": "error", "message": str(e)}

    finally:
        asyncio.run(db.close())


# ── Schedule Manager ─────────────────────────────────────────────────────────


class ScheduleManager:
    """Manager for scan schedules."""

    @staticmethod
    async def create_cron_schedule(
        db: Any,
        name: str,
        target_id: uuid.UUID,
        cron_expression: str,  # e.g., "0 2 * * *" (daily at 2 AM)
        profile: str = "standard",
        config: dict | None = None,
        created_by: uuid.UUID | None = None,
        notify_on_complete: bool = True,
        notify_emails: list[str] | None = None,
    ) -> ScanSchedule:
        """Create a cron-based schedule.

        Args:
            db: Database session
            name: Schedule name
            target_id: Target UUID
            cron_expression: Cron expression (minute hour day month weekday)
            profile: Scan profile
            config: Scan configuration
            created_by: User UUID
            notify_on_complete: Send notification on completion
            notify_emails: Email addresses for notifications

        Returns:
            Created schedule
        """
        # Parse cron expression
        parts = cron_expression.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: minute hour day month weekday")

        schedule = ScanSchedule(
            name=name,
            target_id=target_id,
            schedule_type="cron",
            cron_minute=parts[0],
            cron_hour=parts[1],
            cron_day_of_month=parts[2],
            cron_month_of_year=parts[3],
            cron_day_of_week=parts[4],
            profile=profile,
            config=config or {},
            created_by=created_by,
            notify_on_complete=notify_on_complete,
            notification_emails=notify_emails or [],
        )

        schedule.next_run_at = schedule.get_next_run()
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        logger.info(
            "cron_schedule_created",
            schedule_id=str(schedule.id),
            cron=cron_expression,
        )

        return schedule

    @staticmethod
    async def create_interval_schedule(
        db: Any,
        name: str,
        target_id: uuid.UUID,
        interval_seconds: int,
        profile: str = "standard",
        config: dict | None = None,
        created_by: uuid.UUID | None = None,
    ) -> ScanSchedule:
        """Create an interval-based schedule.

        Args:
            db: Database session
            name: Schedule name
            target_id: Target UUID
            interval_seconds: Interval in seconds
            profile: Scan profile
            config: Scan configuration
            created_by: User UUID

        Returns:
            Created schedule
        """
        if interval_seconds < 300:  # Minimum 5 minutes
            raise ValueError("Minimum interval is 300 seconds (5 minutes)")

        schedule = ScanSchedule(
            name=name,
            target_id=target_id,
            schedule_type="interval",
            interval_seconds=interval_seconds,
            profile=profile,
            config=config or {},
            created_by=created_by,
        )

        schedule.next_run_at = schedule.get_next_run()
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        logger.info(
            "interval_schedule_created",
            schedule_id=str(schedule.id),
            interval_seconds=interval_seconds,
        )

        return schedule

    @staticmethod
    async def create_one_time_schedule(
        db: Any,
        name: str,
        target_id: uuid.UUID,
        scheduled_at: datetime,
        profile: str = "standard",
        config: dict | None = None,
        created_by: uuid.UUID | None = None,
    ) -> ScanSchedule:
        """Create a one-time scheduled scan.

        Args:
            db: Database session
            name: Schedule name
            target_id: Target UUID
            scheduled_at: When to run the scan
            profile: Scan profile
            config: Scan configuration
            created_by: User UUID

        Returns:
            Created schedule
        """
        if scheduled_at < datetime.now(UTC):
            raise ValueError("Scheduled time must be in the future")

        schedule = ScanSchedule(
            name=name,
            target_id=target_id,
            schedule_type="once",
            scheduled_at=scheduled_at,
            profile=profile,
            config=config or {},
            created_by=created_by,
        )

        schedule.next_run_at = scheduled_at
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        logger.info(
            "one_time_schedule_created",
            schedule_id=str(schedule.id),
            scheduled_at=scheduled_at.isoformat(),
        )

        return schedule

    @staticmethod
    async def deactivate_schedule(
        db: Any,
        schedule_id: uuid.UUID,
    ) -> bool:
        """Deactivate a schedule.

        Args:
            db: Database session
            schedule_id: Schedule UUID

        Returns:
            True if deactivated
        """
        from sqlalchemy import select

        result = await db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
        schedule = result.scalar_one_or_none()

        if not schedule:
            return False

        schedule.is_active = False
        schedule.updated_at = datetime.now(UTC)
        await db.commit()

        logger.info(
            "schedule_deactivated",
            schedule_id=str(schedule_id),
        )

        return True

    @staticmethod
    async def activate_schedule(
        db: Any,
        schedule_id: uuid.UUID,
    ) -> bool:
        """Activate a schedule.

        Args:
            db: Database session
            schedule_id: Schedule UUID

        Returns:
            True if activated
        """
        from sqlalchemy import select

        result = await db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
        schedule = result.scalar_one_or_none()

        if not schedule:
            return False

        schedule.is_active = True
        schedule.updated_at = datetime.now(UTC)
        schedule.next_run_at = schedule.get_next_run()
        await db.commit()

        logger.info(
            "schedule_activated",
            schedule_id=str(schedule_id),
        )

        return True


# ── Celery Beat Configuration ────────────────────────────────────────────────


def get_beat_schedule() -> dict[str, dict[str, Any]]:
    """Get Celery Beat schedule configuration.

    Returns:
        Beat schedule dictionary
    """
    return {
        # Cleanup old schedules weekly
        "cleanup-old-schedules": {
            "task": "netra.cleanup_old_schedules",
            "schedule": crontab(minute=0, hour=3, day_of_week="sunday"),  # Sunday 3 AM
        },

        # Check and run due schedules every minute
        "check-due-schedules": {
            "task": "netra.check_and_run_due_schedules",
            "schedule": crontab(minute="*/1"),  # Every minute
        },
    }


@celery_app.task(bind=True, name="netra.check_and_run_due_schedules")
def check_and_run_due_schedules(self) -> dict[str, Any]:
    """Check for due schedules and trigger scans.

    Returns:
        Task result dictionary
    """
    import asyncio

    from sqlalchemy import select

    from netra.db.session import AsyncSessionLocal

    db = AsyncSessionLocal()
    now = datetime.now(UTC)

    try:
        # Find due schedules
        result = asyncio.run(db.execute(
            select(ScanSchedule).where(
                ScanSchedule.is_active is True,
                ScanSchedule.next_run_at <= now,
            )
        ))
        due_schedules = result.scalars().all()

        triggered = []
        for schedule in due_schedules:
            # Trigger scan
            execute_scheduled_scan.delay(str(schedule.id))
            triggered.append(str(schedule.id))

        logger.info(
            "due_schedules_checked",
            triggered_count=len(triggered),
            triggered=triggered,
        )

        return {
            "status": "success",
            "triggered_count": len(triggered),
            "triggered_schedules": triggered,
        }

    except Exception as e:
        logger.error("check_due_schedules_failed", error=str(e))
        return {"status": "error", "message": str(e)}

    finally:
        asyncio.run(db.close())


# ── SLA Breach Checker ────────────────────────────────────────────────────────


@celery_app.task(bind=True, name="netra.check_and_notify_sla_breaches")
def check_and_notify_sla_breaches(self) -> dict:
    """Check for SLA breaches and send notifications.

    Returns:
        Task result dictionary
    """
    import asyncio

    from netra.db.session import AsyncSessionLocal
    from netra.notifications.manager import NotificationManager

    db = AsyncSessionLocal()

    try:
        manager = NotificationManager(db)
        breaches_notified = asyncio.run(manager.check_and_notify_sla_breaches())

        return {
            "status": "success",
            "breaches_notified": breaches_notified,
        }

    except Exception as e:
        logger.error("sla_breach_check_failed", error=str(e))
        return {"status": "error", "message": str(e)}

    finally:
        asyncio.run(db.close())
