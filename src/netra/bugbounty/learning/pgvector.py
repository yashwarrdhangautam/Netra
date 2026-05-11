"""Optional pgvector acceleration for the learning corpus."""
from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def pgvector_literal(embedding: list[float]) -> str:
    """Serialize an embedding as a pgvector literal."""
    return "[" + ",".join(f"{float(value):.12g}" for value in embedding) + "]"


async def sync_embedding_vector(
    session: AsyncSession,
    *,
    table_name: str,
    row_id: Any,
    embedding: list[float],
) -> None:
    """Best-effort sync into a pgvector column when running on PostgreSQL."""
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    await session.execute(
        text(f"UPDATE {table_name} SET embedding_vector = CAST(:embedding AS vector) WHERE id = :row_id"),
        {"embedding": pgvector_literal(embedding), "row_id": row_id},
    )

