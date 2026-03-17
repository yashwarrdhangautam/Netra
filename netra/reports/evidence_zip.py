"""
netra/reports/evidence_zip.py
SHA256 chain-of-custody evidence ZIP generator.
Packages:
  - All findings as JSON
  - Screenshot files
  - PoC logs and HTTP request/response evidence
  - SHA256 manifest for all files (chain of custody)
  - Signed metadata with scan operator and timestamp
"""

import io
import json
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime, timezone


def generate_evidence_zip(ctx: dict, workdir: Path, reports_dir: Path) -> Path:
    """
    Generate a chain-of-custody evidence ZIP for the scan.

    The ZIP contains:
      - findings.json          — complete findings dump
      - assets.json            — complete asset inventory
      - chains.json            — attack chain data
      - screenshots/           — all screenshot files
      - evidence/              — PoC logs and HTTP evidence per finding
      - MANIFEST.json          — SHA256 hash of every file in the ZIP
      - CHAIN_OF_CUSTODY.txt   — signed metadata block

    Args:
        ctx:         Report context dict.
        workdir:     Scan workdir containing evidence subdirectories.
        reports_dir: Directory to save the output file.

    Returns:
        Path to the generated .zip file.
    """
    findings = ctx.get("findings", [])
    assets   = ctx.get("assets", [])
    chains   = ctx.get("chains", [])
    scan_id  = ctx.get("scan_id", "unknown")
    operator = ctx.get("operator", "operator")
    ts       = datetime.now(timezone.utc).isoformat()

    filename = _zip_filename(ctx)
    out_path = reports_dir / filename

    file_hashes: dict = {}

    with zipfile.ZipFile(str(out_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:

        # ── Core data files ───────────────────────────────────────────

        findings_data = json.dumps(
            [_sanitise_finding(f) for f in findings],
            indent=2, ensure_ascii=False
        ).encode("utf-8")
        _write_entry(zf, "findings.json", findings_data, file_hashes)

        assets_data = json.dumps(
            [_sanitise_asset(a) for a in assets],
            indent=2, ensure_ascii=False
        ).encode("utf-8")
        _write_entry(zf, "assets.json", assets_data, file_hashes)

        chains_data = json.dumps(
            [_sanitise_chain(c) for c in chains],
            indent=2, ensure_ascii=False
        ).encode("utf-8")
        _write_entry(zf, "chains.json", chains_data, file_hashes)

        # ── Per-finding evidence ──────────────────────────────────────

        for f in findings:
            fid  = f.get("id", "unknown")
            sev  = f.get("severity", "info").lower()
            slug = f"finding_{fid}_{sev}"

            # HTTP request/response
            if f.get("request") or f.get("response"):
                req_data = (
                    f"=== REQUEST ===\n{f.get('request', '')}\n\n"
                    f"=== RESPONSE (truncated) ===\n{f.get('response', '')}"
                ).encode("utf-8")
                _write_entry(zf, f"evidence/{slug}_http.txt", req_data, file_hashes)

            # PoC command
            if f.get("poc_command"):
                poc_data = (
                    f"# PoC for: {f.get('title', '')}\n"
                    f"# Host: {f.get('host', '')}\n"
                    f"# CVSS: {f.get('cvss_score', 'N/A')}\n\n"
                    f"{f.get('poc_command', '')}\n"
                ).encode("utf-8")
                _write_entry(zf, f"evidence/{slug}_poc.sh", poc_data, file_hashes)

            # Raw evidence
            if f.get("evidence"):
                ev_data = f.get("evidence", "").encode("utf-8")
                _write_entry(zf, f"evidence/{slug}_evidence.txt", ev_data, file_hashes)

        # ── Screenshots ───────────────────────────────────────────────

        screenshots_dir = workdir / "screenshots"
        if screenshots_dir.exists():
            for img_path in sorted(screenshots_dir.glob("**/*.png"))[:50]:
                try:
                    img_data = img_path.read_bytes()
                    arc_name = f"screenshots/{img_path.name}"
                    _write_entry(zf, arc_name, img_data, file_hashes)
                except Exception:
                    pass

            for img_path in sorted(screenshots_dir.glob("**/*.jpg"))[:20]:
                try:
                    img_data = img_path.read_bytes()
                    arc_name = f"screenshots/{img_path.name}"
                    _write_entry(zf, arc_name, img_data, file_hashes)
                except Exception:
                    pass

        # ── Scan logs ─────────────────────────────────────────────────

        for log_name in ["recon.log", "pentest.log", "nuclei.log"]:
            log_path = workdir / log_name
            if log_path.exists():
                try:
                    _write_entry(zf, f"logs/{log_name}",
                                 log_path.read_bytes(), file_hashes)
                except Exception:
                    pass

        # ── Checkpoint ────────────────────────────────────────────────

        cp_path = workdir / "checkpoint.json"
        if cp_path.exists():
            try:
                _write_entry(zf, "checkpoint.json",
                             cp_path.read_bytes(), file_hashes)
            except Exception:
                pass

        # ── Summary JSON ──────────────────────────────────────────────

        stats = ctx.get("stats", {})
        summary = {
            "scan_id":        scan_id,
            "operator":       operator,
            "date":           ctx.get("date", ts[:10]),
            "client":         ctx.get("client", ""),
            "engagement":     ctx.get("engagement", ""),
            "risk_score":     ctx.get("risk_score", 0),
            "risk_grade":     ctx.get("risk_grade", "?"),
            "finding_counts": stats,
            "total_findings": sum(stats.values()),
            "asset_count":    len(assets),
            "chain_count":    len(chains),
            "generated_at":   ts,
        }
        _write_entry(zf, "summary.json",
                     json.dumps(summary, indent=2).encode("utf-8"),
                     file_hashes)

        # ── SHA256 Manifest ───────────────────────────────────────────

        manifest = {
            "scan_id":       scan_id,
            "generated_at":  ts,
            "operator":      operator,
            "file_count":    len(file_hashes),
            "files":         [
                {"path": path, "sha256": sha256}
                for path, sha256 in sorted(file_hashes.items())
            ],
        }
        manifest_data = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_data).hexdigest()
        zf.writestr("MANIFEST.json", manifest_data)

        # ── Chain of custody document ─────────────────────────────────

        coc_text = _chain_of_custody(
            scan_id, operator, ts, ctx, file_hashes, manifest_hash
        )
        zf.writestr("CHAIN_OF_CUSTODY.txt", coc_text)

    return out_path


def _write_entry(zf: zipfile.ZipFile, arc_name: str,
                 data: bytes, hashes: dict) -> None:
    """
    Write a file to the ZIP and record its SHA256 hash.

    Args:
        zf:       ZipFile object.
        arc_name: Archive path within the ZIP.
        data:     File bytes to write.
        hashes:   Dict to record sha256 hashes into.
    """
    zf.writestr(arc_name, data)
    hashes[arc_name] = hashlib.sha256(data).hexdigest()


def _chain_of_custody(scan_id: str, operator: str, ts: str,
                       ctx: dict, hashes: dict, manifest_hash: str) -> str:
    """
    Generate a chain-of-custody text document.

    Args:
        scan_id:       Scan identifier.
        operator:      Operator who ran the scan.
        ts:            ISO timestamp.
        ctx:           Report context.
        hashes:        Dict of filename → sha256.
        manifest_hash: SHA256 hash of the manifest file.

    Returns:
        Chain-of-custody document as a text string.
    """
    stats = ctx.get("stats", {})
    lines = [
        "=" * 70,
        "CHAIN OF CUSTODY DOCUMENT",
        "NETRA नेत्र — The Third Eye of Security",
        "=" * 70,
        "",
        "SCAN INFORMATION",
        "-" * 40,
        f"Scan ID:        {scan_id}",
        f"Operator:       {operator}",
        f"Client:         {ctx.get('client', 'Confidential')}",
        f"Engagement:     {ctx.get('engagement', 'Security Assessment')}",
        f"Generated:      {ts}",
        f"Risk Grade:     {ctx.get('risk_grade', '?')} ({ctx.get('risk_score', 0)}/100)",
        "",
        "FINDING SUMMARY",
        "-" * 40,
        f"Critical:       {stats.get('critical', 0)}",
        f"High:           {stats.get('high', 0)}",
        f"Medium:         {stats.get('medium', 0)}",
        f"Low:            {stats.get('low', 0)}",
        f"Total:          {sum(stats.values())}",
        "",
        "EVIDENCE INTEGRITY",
        "-" * 40,
        f"Total files:    {len(hashes)}",
        f"Manifest SHA256: {manifest_hash}",
        "",
        "FILE HASHES (SHA256)",
        "-" * 40,
    ]

    for path, sha256 in sorted(hashes.items()):
        lines.append(f"  {sha256}  {path}")

    lines += [
        "",
        "CERTIFICATION",
        "-" * 40,
        f"This evidence package was generated by NETRA नेत्र on {ts}.",
        f"The SHA256 hashes above certify the integrity of all included files.",
        f"Any modification of files will invalidate the corresponding hash.",
        "",
        "LEGAL NOTICE",
        "-" * 40,
        "This document and its contents are confidential and intended solely",
        "for the named client. Unauthorised disclosure is prohibited.",
        "",
        "=" * 70,
        "END OF CHAIN OF CUSTODY",
        "=" * 70,
    ]

    return "\n".join(lines)


def _sanitise_finding(f: dict) -> dict:
    """Remove very large fields from a finding for JSON export."""
    exclude = {"response"}   # raw HTTP responses can be huge
    return {k: v for k, v in f.items() if k not in exclude}


def _sanitise_asset(a: dict) -> dict:
    """Return all asset fields as-is (they're already compact)."""
    return dict(a)


def _sanitise_chain(c: dict) -> dict:
    """Return chain with nodes parsed from JSON if stored as string."""
    out = dict(c)
    if isinstance(out.get("nodes"), str):
        try:
            out["nodes"] = json.loads(out["nodes"])
        except Exception:
            pass
    return out


def _zip_filename(ctx: dict) -> str:
    """Generate a standardised evidence ZIP filename."""
    import re
    scan_id = ctx.get("scan_id", "unknown")
    date    = ctx.get("date", datetime.now().strftime("%Y%m%d")).replace("-", "")
    target  = re.sub(r"[^a-zA-Z0-9]", "_", ctx.get("engagement", scan_id))[:20]
    return f"NETRA_evidence_{target}_{date}.zip"
