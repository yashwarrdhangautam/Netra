"""Recon manifest (schema 1.0): build it from live-host results and render the arsenal map.

The manifest is the single file a hunt reads to know what exists on a target. The arsenal map is a
short per-host list: what runs there, what protects it, and the first checks to try. Both are
built from data the recon phase already collects; neither sends traffic.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from netra.intel.bypass_checklist import checklist_for

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "recon-manifest.schema.json"
REQUIRED_KEYS = (
    "schema_version",
    "target",
    "generated_at",
    "producers",
    "counts",
    "assets",
    "ranked_surface",
    "secrets",
    "identity_fabric",
)
_ASSET_KEYS = ("host", "url", "status", "tech", "protections", "source")


def build_manifest(
    target: str,
    live_hosts: Iterable[dict[str, Any]],
    *,
    producer: str = "netra-recon/1.0",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble a manifest from httpx-style host rows (see HttpxTool._row_to_finding)."""
    assets = []
    for row in live_hosts:
        url = row.get("url")
        host = urlsplit(url).hostname if url else row.get("hostname")
        if not host:
            continue
        assets.append(
            {
                "host": host,
                "url": url,
                "status": row.get("status_code"),
                "title": row.get("title"),
                "tech": list(row.get("tech") or []),
                "protections": list(row.get("protections") or []),
                "source": "httpx",
            }
        )
    ranked = [_rank(a) for a in assets]
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "producers": [producer],
        "counts": {"hosts": len(assets), "live": sum(1 for a in assets if a["status"])},
        "assets": assets,
        "ranked_surface": [r for r in ranked if r is not None],
        "secrets": [],
        "identity_fabric": {},
    }


def _rank(asset: dict[str, Any]) -> dict[str, Any] | None:
    """Prioritise a host. Anything with a protection has checks to try, so it becomes P2 at least."""
    if not asset["url"]:
        return None
    if asset["protections"]:
        priority = "P1" if "waf" not in asset["protections"] else "P2"
    else:
        priority = "P2" if asset["status"] in (200, 301, 302, 401, 403) else "KILL"
    return {
        "url": asset["url"],
        "host": asset["host"],
        "bug_classes": [],
        "priority": priority,
        "rationale": _rationale(asset),
    }


def _rationale(asset: dict[str, Any]) -> str:
    parts = []
    if asset["tech"]:
        parts.append("tech: " + ", ".join(asset["tech"][:5]))
    if asset["protections"]:
        parts.append("protections: " + ", ".join(asset["protections"]))
    if asset["status"] is not None:
        parts.append(f"status {asset['status']}")
    return "; ".join(parts) or "no fingerprint"


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    """Return a list of problems. An empty list means the manifest matches schema 1.0."""
    problems = [f"missing key: {k}" for k in REQUIRED_KEYS if k not in manifest]
    if problems:
        return problems
    if manifest["schema_version"] != SCHEMA_VERSION:
        problems.append("schema_version must be 1.0")
    if not isinstance(manifest["target"], str) or not manifest["target"]:
        problems.append("target must be a non-empty string")
    for i, asset in enumerate(manifest["assets"]):
        missing = [k for k in _ASSET_KEYS if k not in asset]
        if missing:
            problems.append(f"assets[{i}] missing {', '.join(missing)}")
    for i, item in enumerate(manifest["ranked_surface"]):
        if item.get("priority") not in ("P1", "P2", "KILL"):
            problems.append(f"ranked_surface[{i}] priority must be P1, P2 or KILL")
    return problems


def write_manifest(manifest: dict[str, Any], out_dir: Path) -> Path:
    """Write recon/<target>/manifest.json under out_dir after validating it."""
    problems = validate_manifest(manifest)
    if problems:
        raise ValueError("invalid manifest: " + "; ".join(problems))
    path = out_dir / manifest["target"] / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def render_arsenal(manifest: dict[str, Any]) -> str:
    """Markdown map: one block per host with its stack, protections and first checks."""
    lines = [f"# Arsenal map: {manifest['target']}", ""]
    lines.append(f"Hosts: {manifest['counts']['hosts']}, live: {manifest['counts']['live']}")
    lines.append("")
    for item in manifest["ranked_surface"]:
        asset = next((a for a in manifest["assets"] if a["url"] == item["url"]), None)
        lines.append(f"## {item['priority']} {item['url']}")
        lines.append(f"- {item['rationale']}")
        if asset and asset["protections"]:
            lines.append("- First checks:")
            for entry in checklist_for(asset["protections"]):
                lines.append(f"  - [{entry.label}] {entry.check}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
