"""Payload library: parse a local PayloadsAllTheThings checkout into searchable passages.

The source is MIT licensed (Swissky and contributors). Each passage keeps its topic, the file it
came from and the upstream commit, so every payload can be traced and attributed. Nothing is
fetched at import time: callers point the parser at a checkout made at PAYLOADS_REF.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

PAYLOADS_REPO = "https://github.com/swisskyrepo/PayloadsAllTheThings"
PAYLOADS_REF = "08ea40e77db3f42ef8f20c65196f3936a19b6c86"
PAYLOADS_LICENCE = "MIT"
MAX_PASSAGE_CHARS = 2000
SKIP_DIRS = {"Methodology and Resources", "Images", "Files"}
_FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)
_HEADING = re.compile(r"^#{2,3}\s+(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Passage:
    topic: str
    section: str
    source: str  # path relative to the checkout
    text: str
    commit: str = PAYLOADS_REF
    licence: str = PAYLOADS_LICENCE

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def parse_readme(topic: str, rel_path: str, markdown: str) -> list[Passage]:
    """Split one README into passages: each fenced block, under the nearest heading above it."""
    passages: list[Passage] = []
    headings = [(m.start(), m.group(1)) for m in _HEADING.finditer(markdown)]
    for match in _FENCE.finditer(markdown):
        body = match.group(1).strip()
        if not body:
            continue
        section = "General"
        for pos, title in headings:
            if pos < match.start():
                section = title
            else:
                break
        passages.append(
            Passage(
                topic=topic,
                section=section,
                source=rel_path,
                text=body[:MAX_PASSAGE_CHARS],
            )
        )
    return passages


def load_payloads(root: Path, topics: set[str] | None = None) -> list[Passage]:
    """Parse every topic README under the checkout root. Unreadable files are skipped."""
    out: list[Passage] = []
    if not root.is_dir():
        return out
    for readme in sorted(root.glob("*/README.md")):
        topic = readme.parent.name
        if topic.startswith((".", "_")) or topic in SKIP_DIRS:
            continue
        if topics and topic not in topics:
            continue
        try:
            markdown = readme.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = readme.relative_to(root).as_posix()
        out.extend(parse_readme(topic, rel, markdown))
    return out


def search(passages: list[Passage], query: str = "", topic: str | None = None, limit: int = 50):
    """Case-insensitive filter by topic and free text, capped at limit."""
    q = query.lower().strip()
    hits = []
    for p in passages:
        if topic and p.topic.lower() != topic.lower():
            continue
        if q and q not in p.text.lower() and q not in p.section.lower():
            continue
        hits.append(p)
        if len(hits) >= limit:
            break
    return hits


def checkout_dir(tools_dir: Path) -> Path:
    return tools_dir / "payloads" / PAYLOADS_REF[:12]


def sync_checkout(tools_dir: Path) -> Path:
    """Fetch the upstream repository at PAYLOADS_REF into tools_dir. Returns the checkout path."""
    import subprocess

    dest = checkout_dir(tools_dir)
    if (dest / ".git").is_dir():
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
        if head == PAYLOADS_REF:
            return dest
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(dest)], check=True, timeout=60)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", PAYLOADS_REPO, PAYLOADS_REF],
        check=True,
        timeout=600,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True, timeout=120
    )
    return dest
