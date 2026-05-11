"""Schedule management API routes."""
import uuid
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.session import get_db
from netra.api.routes.auth import get_current_active_user
from netra.db.models.user import User
from netra.db.models.scan import Scan
from netra.worker.scheduler import (
    ScanSchedule,
    ScheduleManager,
    execute_scheduled_scan,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/schedules", tags=["Schedules"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

from pydantic import BaseModel, Field, validator


class CronScheduleCreate(BaseModel):
    """Create cron schedule request."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    target_id: uuid.UUID
    cron_expression: str = Field(
        ...,
        description="Cron expression: minute hour day month weekday (e.g., '0 2 * * *')"
    )
    profile: str = "standard"
    notify_on_complete: bool = True
    notify_emails: list[str] = Field(default_factory=list)

    @validator("cron_expression")
    def validate_cron(cls, v):
        parts = v.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: minute hour day month weekday")
        return v


class IntervalScheduleCreate(BaseModel):
    """Create interval schedule request."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    target_id: uuid.UUID
    interval_seconds: int = Field(..., ge=300)  # Minimum 5 minutes
    profile: str = "standard"

    @validator("interval_seconds")
    def validate_interval(cls, v):
        if v < 300:
            raise ValueError("Minimum interval is 300 seconds (5 minutes)")
        return v


class OneTimeScheduleCreate(BaseModel):
    """Create one-time schedule request."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    target_id: uuid.UUID
    scheduled_at: datetime
    profile: str = "standard"

    @validator("scheduled_at")
    def validate_future(cls, v):
        if v < datetime.now(timezone.utc):
            raise ValueError("Scheduled time must be in the future")
        return v


class ScheduleResponse(BaseModel):
    """Schedule response schema."""

    id: str
    name: str
    description: str | None
    schedule_type: str
    target_id: str
    profile: str
    is_active: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    total_runs: int
    created_at: datetime

    class Config:
        from_attributes = True


# ── Schedule Routes ──────────────────────────────────────────────────────────


@router.post("/cron", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_cron_schedule(
    request: CronScheduleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Create a cron-based recurring scan schedule.

    Args:
        request: Schedule creation request
        db: Database session
        current_user: Authenticated user

    Returns:
        Created schedule

    Examples:
        - Daily at 2 AM: "0 2 * * *"
        - Every 6 hours: "0 */6 * * *"
        - Weekly on Monday 9 AM: "0 9 * * mon"
        - Monthly on 1st: "0 2 1 * *"
    """
    try:
        schedule = await ScheduleManager.create_cron_schedule(
            db=db,
            name=request.name,
            target_id=request.target_id,
            cron_expression=request.cron_expression,
            profile=request.profile,
            created_by=current_user.id,
            notify_on_complete=request.notify_on_complete,
            notify_emails=request.notify_emails,
        )

        return ScheduleResponse.model_validate(schedule)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/interval", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_interval_schedule(
    request: IntervalScheduleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Create an interval-based recurring scan schedule.

    Args:
        request: Schedule creation request
        db: Database session
        current_user: Authenticated user

    Returns:
        Created schedule
    """
    try:
        schedule = await ScheduleManager.create_interval_schedule(
            db=db,
            name=request.name,
            target_id=request.target_id,
            interval_seconds=request.interval_seconds,
            profile=request.profile,
            created_by=current_user.id,
        )

        return ScheduleResponse.model_validate(schedule)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/once", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_one_time_schedule(
    request: OneTimeScheduleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Create a one-time scheduled scan.

    Args:
        request: Schedule creation request
        db: Database session
        current_user: Authenticated user

    Returns:
        Created schedule
    """
    try:
        schedule = await ScheduleManager.create_one_time_schedule(
            db=db,
            name=request.name,
            target_id=request.target_id,
            scheduled_at=request.scheduled_at,
            profile=request.profile,
            created_by=current_user.id,
        )

        return ScheduleResponse.model_validate(schedule)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    is_active: bool | None = Query(None),
    schedule_type: str | None = Query(None),
) -> list[ScheduleResponse]:
    """List all scan schedules.

    Args:
        db: Database session
        current_user: Authenticated user
        is_active: Filter by active status
        schedule_type: Filter by schedule type

    Returns:
        List of schedules
    """
    query = select(ScanSchedule)

    if is_active is not None:
        query = query.where(ScanSchedule.is_active == is_active)

    if schedule_type is not None:
        query = query.where(ScanSchedule.schedule_type == schedule_type)

    # Admins see all, others see only their own
    if not current_user.is_admin():
        query = query.where(ScanSchedule.created_by == current_user.id)

    result = await db.execute(query.order_by(ScanSchedule.created_at.desc()))
    schedules = result.scalars().all()

    return [ScheduleResponse.model_validate(s) for s in schedules]


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Get a specific schedule.

    Args:
        schedule_id: Schedule UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Schedule details
    """
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    # Check permissions
    if not current_user.is_admin() and schedule.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    return ScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Delete a schedule.

    Args:
        schedule_id: Schedule UUID
        db: Database session
        current_user: Authenticated user
    """
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    # Check permissions
    if not current_user.is_admin() and schedule.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    await db.delete(schedule)
    await db.commit()


@router.post("/{schedule_id}/deactivate", response_model=ScheduleResponse)
async def deactivate_schedule(
    schedule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Deactivate a schedule.

    Args:
        schedule_id: Schedule UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated schedule
    """
    success = await ScheduleManager.deactivate_schedule(db, schedule_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    return ScheduleResponse.model_validate(schedule)


@router.post("/{schedule_id}/activate", response_model=ScheduleResponse)
async def activate_schedule(
    schedule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ScheduleResponse:
    """Activate a schedule.

    Args:
        schedule_id: Schedule UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated schedule
    """
    success = await ScheduleManager.activate_schedule(db, schedule_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    return ScheduleResponse.model_validate(schedule)


@router.post("/{schedule_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_schedule_now(
    schedule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> dict:
    """Trigger a scheduled scan immediately.

    Args:
        schedule_id: Schedule UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Task result
    """
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    # Check permissions
    if not current_user.is_admin() and schedule.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Trigger scan execution
    task = execute_scheduled_scan.delay(str(schedule_id))

    return {
        "status": "accepted",
        "task_id": task.id,
        "schedule_id": str(schedule_id),
        "message": "Scan triggered",
    }
