"""Model-aware token accounting for agentic hunts.

NETRA-native, adapted from the Strix (Apache-2.0) context-budget approach:
resolve a model's input window, cap output, and count tokens. Dependency-light
by design — token counting uses ``tiktoken`` when it is importable (as a
proxy encoding) and otherwise a conservative chars/4 estimate, so budget
checks work with no extra dependency. These numbers gate spend; they are
estimates, not billing-accurate counts.
"""

from __future__ import annotations

from functools import lru_cache

# Approximate input context windows by model family. Conservative and only
# used to decide when to trim context, never to bill. Extend as needed.
_CONTEXT_WINDOWS = {
    "claude": 200_000,
    "llama": 128_000,
    "mistral": 32_000,
    "qwen": 32_000,
}
_DEFAULT_CONTEXT = 128_000
_DEFAULT_OUTPUT = 8_192
_CHARS_PER_TOKEN = 4  # rough fallback: ~4 characters per token


def _family(model: str) -> str:
    m = (model or "").lower()
    for key in _CONTEXT_WINDOWS:
        if key in m:
            return key
    return ""


def context_window(model: str, *, fallback: int = _DEFAULT_CONTEXT) -> int:
    """Input-token capacity for ``model`` (family-matched, else ``fallback``)."""
    return _CONTEXT_WINDOWS.get(_family(model), fallback)


def output_limit(model: str) -> int:
    """Conservative max output tokens for ``model``."""
    return _DEFAULT_OUTPUT


@lru_cache(maxsize=4)
def _encoder():
    try:
        import tiktoken

        return tiktoken.get_encoding("cl100k_base")
    except Exception:  # noqa: BLE001 - tokenizer optional; fall back to heuristic
        return None


def count_tokens(text: str, model: str = "") -> int:
    """Best-effort token count. Never raises.

    Uses tiktoken (proxy encoding) when available, else a conservative
    chars/4 estimate that is a safe upper-ish bound for budget gating.
    """
    if not text:
        return 0
    enc = _encoder()
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:  # noqa: BLE001 - defensive; heuristic fallback
            pass
    return max(1, (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)
