"""Embedding helpers for local-first corpus retrieval."""
from __future__ import annotations

import hashlib
import math
from collections import Counter

import httpx

from netra.core.config import settings

EMBEDDING_DIM = 768
OLLAMA_EMBED_MODEL = "nomic-embed-text"
HASHED_EMBED_MODEL = "hashed-token-v1"


def _normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]


def _hashed_embedding(text: str) -> list[float]:
    vector = [0.0] * EMBEDDING_DIM
    tokens = [token.strip().lower() for token in text.split() if token.strip()]
    counts = Counter(tokens)
    for token, weight in counts.items():
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:4], "big") % EMBEDDING_DIM
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[bucket] += sign * float(weight)
    return _normalize(vector)


async def embed(text: str) -> list[float]:
    embedding, _version = await embed_with_version(text)
    return embedding


def current_embedding_model_version() -> str:
    """Return the preferred local embedding model identifier."""
    return f"ollama:{OLLAMA_EMBED_MODEL}:{EMBEDDING_DIM}"


async def embed_with_version(text: str) -> tuple[list[float], str]:
    """Embed text locally, preferring Ollama and falling back deterministically."""
    payload = text.strip()
    if not payload:
        return [0.0] * EMBEDDING_DIM, current_embedding_model_version()
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                f"{settings.ollama_base_url}/api/embeddings",
                json={"model": OLLAMA_EMBED_MODEL, "prompt": payload[:8000]},
            )
            response.raise_for_status()
            data = response.json()
            embedding = data.get("embedding") or data.get("embeddings", [None])[0]
            if isinstance(embedding, list) and embedding:
                if len(embedding) < EMBEDDING_DIM:
                    embedding = embedding + [0.0] * (EMBEDDING_DIM - len(embedding))
                return (
                    _normalize([float(value) for value in embedding[:EMBEDDING_DIM]]),
                    current_embedding_model_version(),
                )
    except Exception:
        pass
    return _hashed_embedding(payload), f"local:{HASHED_EMBED_MODEL}:{EMBEDDING_DIM}"


async def embed_batch(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts while preserving order and determinism."""
    return [await embed(text) for text in texts]
