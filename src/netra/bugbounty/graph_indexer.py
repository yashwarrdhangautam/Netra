"""Graphify integration — index code, recon output, and submission history.

We use Graphify in **local-output mode only** (markdown / HTML / JSON). The Neo4j
push path is disabled until upstream issue safishamsi/graphify#84 (Cypher injection
in to_cypher() / push_to_neo4j()) is patched and reviewed.

Three things get indexed:
    1. NETRA's own codebase (`indexer.index_codebase()`) — so the agent can answer
       'where is the scope validator called' without grep.
    2. Recon output per program (`indexer.index_recon_output()`) — produces a graph
       of subdomain → IP → port → service → tech → finding edges.
    3. Submission history (`indexer.index_submissions()`) — exported from bb_submissions
       + bb_dedup_signatures into Graphify's JSON ingestion format. The deduper
       queries this.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import structlog
from netra.scanner.tools.process_control import register_process, unregister_process

logger = structlog.get_logger()


class GraphifyNotAvailable(RuntimeError):
    """Raised when the graphify CLI is missing from PATH."""


def _check_available() -> str:
    """Return the path to the graphify binary, or raise."""
    binary = shutil.which("graphify")
    if not binary:
        raise GraphifyNotAvailable(
            "graphify CLI not found on PATH. Install with `pip install graphify` "
            "(or follow https://graphify.net/ install instructions)."
        )
    return binary


@dataclass
class IndexResult:
    """Outcome of a single index operation."""

    target: str
    output_dir: Path
    nodes: int
    edges: int
    success: bool
    error: str | None = None


async def _run_graphify(args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run graphify CLI asynchronously, capture stdout/stderr."""
    binary = _check_available()
    creation_kwargs: dict[str, object] = {}
    if os.name == "nt":
        creation_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        creation_kwargs["start_new_session"] = True
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **creation_kwargs,
    )
    register_process(proc.pid)
    try:
        stdout, stderr = await proc.communicate()
    finally:
        unregister_process(proc.pid)
    return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


async def index_codebase(
    src_root: Path,
    output_dir: Path,
    *,
    output_format: str = "json",
) -> IndexResult:
    """Index a codebase folder into a local graph.

    output_format must be one of: json, markdown, html.
    Neo4j push is intentionally NOT supported — see module docstring.
    """
    if output_format not in {"json", "markdown", "html"}:
        raise ValueError(f"unsupported output_format: {output_format}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    graph_path = output_dir / "graphify-out" / "graph.json"
    manifest = output_dir / ".netra_graphify_mtime"
    latest_mtime = max((p.stat().st_mtime for p in Path(src_root).rglob("*") if p.is_file()), default=0)
    if graph_path.exists() and manifest.exists():
        try:
            if float(manifest.read_text()) >= latest_mtime:
                return IndexResult(str(src_root), output_dir, nodes=0, edges=0, success=True)
        except ValueError:
            pass

    args = ["extract", str(src_root), "--out", str(output_dir), "--backend", os.getenv("GRAPHIFY_BACKEND", "ollama")]
    rc, out, err = await _run_graphify(args)
    if rc != 0:
        logger.error("bb.graphify.index_failed", target=str(src_root), rc=rc, stderr=err[:500])
        return IndexResult(
            target=str(src_root),
            output_dir=output_dir,
            nodes=0, edges=0,
            success=False,
            error=err[:500],
        )

    # Parse the JSON output for node / edge counts if available.
    nodes = edges = 0
    if graph_path.exists():
        try:
            data = json.loads(graph_path.read_text())
            nodes = len(data.get("nodes", []))
            edges = len(data.get("links", data.get("edges", [])))
        except (json.JSONDecodeError, ValueError):
            pass
    manifest.write_text(str(latest_mtime))

    logger.info("bb.graphify.indexed", target=str(src_root), nodes=nodes, edges=edges)
    return IndexResult(
        target=str(src_root), output_dir=output_dir,
        nodes=nodes, edges=edges, success=True,
    )


async def index_recon_output(program_handle: str, output_root: Path) -> IndexResult:
    """Index ~/netra_output/bb/<program> into a graph."""
    src = Path("~").expanduser() / "netra_output" / "bb" / program_handle
    if not src.exists():
        return IndexResult(
            target=str(src), output_dir=output_root,
            nodes=0, edges=0, success=False,
            error=f"recon output dir does not exist: {src}",
        )
    return await index_codebase(src, output_root / program_handle / "graph", output_format="json")


def export_submissions_json(submissions: list[dict], output_path: Path) -> Path:
    """Export submission history as Graphify-ingestible JSON.

    Graphify's JSON ingestion expects a list of records with at minimum 'id', 'type',
    'attrs', and an optional 'edges' list. We map BBSubmission rows to this shape.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for s in submissions:
        records.append({
            "id": str(s["id"]),
            "type": "submission",
            "attrs": {
                "title": s.get("title"),
                "severity": s.get("severity"),
                "status": s.get("status"),
                "program_id": str(s.get("program_id")),
                "vuln_class": s.get("vuln_class"),
                "asset_path": s.get("asset_path"),
            },
            "edges": [
                {"to": str(s["program_id"]), "rel": "for_program"},
                {"to": str(s["finding_id"]), "rel": "from_finding"},
            ],
        })
    output_path.write_text(json.dumps(records, indent=2))
    logger.info("bb.graphify.submissions_exported", count=len(records), path=str(output_path))
    return output_path
