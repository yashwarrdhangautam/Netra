"""Strict server-owned scan authorization records."""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Action = Literal[
    "passive_recon", "http_probe", "port_scan", "vulnerability_scan", "active_test", "retest"
]
Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


class AuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_reference: str = Field(min_length=1, max_length=2048)
    expires_at: AwareDatetime
    allowed_actions: list[Action] = Field(min_length=1)
    http_methods: list[Method] = Field(min_length=1)
    ports: list[Annotated[int, Field(strict=True, ge=1, le=65535)]] = Field(min_length=1)
    max_requests_per_second: int = Field(ge=1, le=300)

    @field_validator("evidence_reference")
    @classmethod
    def evidence_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence reference must be nonblank")
        return value.strip()

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        if any(isinstance(v, bool) or not 1 <= v <= 65535 for v in values):
            raise ValueError("invalid port")
        return values

    @model_validator(mode="after")
    def unique_values(self) -> Self:
        for values in (self.allowed_actions, self.http_methods, self.ports):
            if len(values) != len(set(values)):
                raise ValueError("duplicate policy values")
        return self


class AuthorizationRecord(AuthorizationRequest):
    version: Literal[1] = 1
    authorization_id: UUID
    authorized_by: UUID
    authorized_at: AwareDatetime
    policy_version: int = Field(ge=1)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at <= self.authorized_at:
            raise ValueError("expiry must follow authorization")
        return self
