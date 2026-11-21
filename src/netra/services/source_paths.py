"""Source path containment for code scans (spec S6).

A source path must resolve, symlinks included, to a directory inside one
configured base directory. Anything else is refused before a tool runs.
"""

from __future__ import annotations

from pathlib import Path


def resolve_source_path(path: str | Path, *, base_dir: str | Path) -> Path:
    """Return the resolved directory for ``path`` if it is contained in ``base_dir``.

    Relative paths are interpreted against ``base_dir``. Absolute paths are
    accepted only when they resolve inside it.

    Raises:
        ValueError: the path escapes the base, is not a directory, or does not exist.
    """
    base = Path(base_dir).resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve()

    if resolved != base and base not in resolved.parents:
        raise ValueError("source path is outside the permitted base directory")
    if not resolved.is_dir():
        raise ValueError("source path is not an existing directory")
    return resolved
