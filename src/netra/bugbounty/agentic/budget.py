"""Budget enforcement for agentic hunts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class HuntBudget:
    max_tools: int = 30
    wallclock_minutes: int = 60
    per_tool_concurrency: int = 3
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tools_used: int = 0

    def record_tool(self) -> None:
        self.tools_used += 1

    def exhausted(self) -> bool:
        if self.tools_used >= self.max_tools:
            return True
        return datetime.now(UTC) >= self.started_at + timedelta(minutes=self.wallclock_minutes)
