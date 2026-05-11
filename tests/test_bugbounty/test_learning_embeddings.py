"""Tests for local-first corpus embeddings."""

from __future__ import annotations

import pytest

from netra.bugbounty.learning.embeddings import (
    EMBEDDING_DIM,
    current_embedding_model_version,
    embed,
    embed_batch,
    embed_with_version,
)
from netra.bugbounty.learning.pgvector import pgvector_literal


@pytest.mark.asyncio
async def test_embed_falls_back_deterministically(monkeypatch) -> None:
    async def fail_post(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("ollama unavailable")

    monkeypatch.setattr("httpx.AsyncClient.post", fail_post)

    first = await embed("shopify idor webhook")
    second = await embed("shopify idor webhook")

    assert len(first) == EMBEDDING_DIM
    assert first == second
    assert any(value != 0 for value in first)


@pytest.mark.asyncio
async def test_embed_batch_preserves_order(monkeypatch) -> None:
    async def fail_post(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("ollama unavailable")

    monkeypatch.setattr("httpx.AsyncClient.post", fail_post)

    vectors = await embed_batch(["first query", "second query"])
    assert len(vectors) == 2
    assert len(vectors[0]) == EMBEDDING_DIM
    assert vectors[0] != vectors[1]


@pytest.mark.asyncio
async def test_embed_with_version_reports_fallback_model(monkeypatch) -> None:
    async def fail_post(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("ollama unavailable")

    monkeypatch.setattr("httpx.AsyncClient.post", fail_post)

    vector, version = await embed_with_version("shopify idor webhook")
    assert len(vector) == EMBEDDING_DIM
    assert version.startswith("local:")
    assert current_embedding_model_version().startswith("ollama:")


def test_pgvector_literal_serializes_embedding() -> None:
    literal = pgvector_literal([0.5, -1.25, 3.0])
    assert literal == "[0.5,-1.25,3]"
