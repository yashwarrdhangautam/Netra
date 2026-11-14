"""Pinned nuclei template set: a fixed upstream commit, checked before a scan uses it.

Scans should be repeatable. Using whatever the template repository's default branch holds on a
given day makes results drift without anyone noticing, so the wrapper only uses a checkout whose
HEAD matches PINNED_REF.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates"
PINNED_REF = "1cb2d50b4f0f5cbdb600165b0afe556b4623f29a"
NUCLEI_TEMPLATES_LICENCE = "MIT"


def pinned_dir(tools_dir: Path) -> Path:
    return tools_dir / "nuclei-templates" / PINNED_REF[:12]


def is_pinned(path: Path) -> bool:
    """True when path is a git checkout whose HEAD is exactly PINNED_REF."""
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and out.stdout.strip() == PINNED_REF


def sync_pinned(tools_dir: Path) -> Path:
    """Clone the template repository and check out PINNED_REF. Returns the checkout path."""
    dest = pinned_dir(tools_dir)
    if is_pinned(dest):
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(dest)], check=True, timeout=60)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", NUCLEI_TEMPLATES_REPO, PINNED_REF],
        check=True,
        timeout=600,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True, timeout=120
    )
    if not is_pinned(dest):
        raise RuntimeError("nuclei template checkout does not match the pinned commit")
    return dest


def template_args(tools_dir: Path) -> list[str]:
    """Extra nuclei arguments when the pinned checkout is present; empty otherwise."""
    path = pinned_dir(tools_dir)
    return ["-templates", str(path)] if is_pinned(path) else []
