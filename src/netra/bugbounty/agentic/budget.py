"""Budget enforcement for agentic hunts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class HuntBudget:
    """Bounds a single hunt by tool count, wall-clock time, and LLM tokens.

    The token ceiling is the Sprint 1 addition: it stops a hunt that is
    burning tokens even while the tool and time budgets are untouched.
    """

    max_tools: int = 30
    wallclock_minutes: int = 60
    per_tool_concurrency: int = 3
    max_tokens: int = 50_000
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tools_used: int = 0
    tokens_used: int = 0

    def record_tool(self) -> None:
        self.tools_used += 1

    def record_tokens(self, count: int) -> None:
        if count > 0:
            self.tokens_used += count

    def tokens_remaining(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    def exhaustion_reason(self) -> str | None:
        """Why the budget is spent, or None if it still has room."""
        if self.tools_used >= self.max_tools:
            return "max_tools"
        if self.tokens_used >= self.max_tokens:
            return "max_tokens"
        if datetime.now(UTC) >= self.started_at + timedelta(minutes=self.wallclock_minutes):
            return "wallclock"
        return None

    def exhausted(self) -> bool:
        return self.exhaustion_reason() is not None
