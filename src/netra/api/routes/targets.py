"""Target routes for managing scan targets with SSRF protection."""
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_current_active_user
from netra.core.rate_limiter import RateLimitProfiles, rate_limit
from netra.core.ssrf_protection import SSRFProtectionError, validate_scan_target
from netra.db.models.target import Target
from netra.db.models.user import User
from netra.db.session import get_db

logger = structlog.get_logger()

router = APIRouter(prefix="/targets", tags=["Targets"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class TargetCreate(BaseModel):
    """Create target request."""

    name: str = Field(..., min_length=1, max_length=255)
    target_type: str  # domain, ip, url, ip_range
    value: str
    scope_includes: list[str] = Field(default_factory=list)
    scope_excludes: list[str] = Field(default_factory=list)


class TargetUpdate(BaseModel):
    """Update target request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    value: str | None = None
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None


class TargetListResponse(BaseModel):
    """Target list item response."""

    id: str
    name: str
    target_type: str
    value: str
    created_at: str

    class Config:
        from_attributes = True


class TargetResponse(BaseModel):
    """Target response."""

    id: str
    name: str
    target_type: str
    value: str
    scope_includes: dict | None
    scope_excludes: dict | None
    metadata: dict | None
    created_at: str

    class Config:
        from_attributes = True


class TargetValidationResponse(BaseModel):
    """Target validation response."""

    valid: bool
    normalized: str | None
    resolved_ips: list[str] | None
    error: str | None
    violation_type: str | None


# ── Target Routes ────────────────────────────────────────────────────────────


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
@rate_limit(RateLimitProfiles.SCAN_CREATE)
async def create_target(
    payload: TargetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> TargetResponse:
    """Create a new target with SSRF validation.

    Args:
        payload: Target creation data
        db: Database session
        current_user: Authenticated user

    Returns:
        Created target details

    Raises:
        HTTPException: If target validation fails or SSRF violation detected
    """
    try:
        # Validate target with SSRF protection
        validated = await validate_scan_target(
            target_type=payload.target_type,
            value=payload.value,
        )

        # Create target model
        target = Target(
            id=uuid.uuid4(),
            user_id=current_user.id,
            name=payload.name,
            target_type=payload.target_type,
            value=payload.value,
            scope_includes=payload.scope_includes or [],
            scope_excludes=payload.scope_excludes or [],
            metadata={
                "normalized": validated.get("normalized"),
                "resolved_ips": validated.get("resolved_ips"),
            },
        )

        # Add to database
        db.add(target)
        await db.commit()

        logger.info(
            "target_created",
            target_id=str(target.id),
            user_id=str(current_user.id),
            target_type=target.target_type,
        )

        return TargetResponse.from_attributes(target)

    except SSRFProtectionError as e:
        logger.warning(
            "ssrf_violation_detected",
            user_id=str(current_user.id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {str(e)}",
        ) from e
    except Exception as e:
        logger.error("target_creation_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create target",
        ) from e
