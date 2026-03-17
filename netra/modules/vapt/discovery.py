"""
recon/discovery.py
Live host discovery + technology fingerprinting via httpx.
Also handles WAF detection so pentest engine can adapt payloads.
"""

import json
from pathlib import Path
from typing import List, Dict

from netra.core.config import CONFIG
from netra.core.utils  import run_cmd, status, tool_exists, write_targets_file, C
from netra.core.database import FindingsDB


def discover_live_hosts(
    targets_file: str,
    workdir: str,
    scan_id: str = "",
) -> tuple:
    """
    Run httpx on all targets. Returns (live_urls_file, tech_map_file).
    live_urls_file  — one URL per line, all responding hosts
    tech_map_file   — JSON: {url: {tech_stack, status, title, ...}}
    """
    workdir   = Path(workdir)
    recon_dir = workdir / "recon"
    recon_dir.mkdir(exist_ok=True)

    live_file = str(recon_dir / "live_urls.txt")
    json_file = str(recon_dir / "httpx.json")

    if not tool_exists("httpx"):
        status("httpx not found", "error")
        return live_file, json_file

    # Build httpx command
    cmd = [
        "httpx",
        "-l", targets_file,
        "-o", live_file,
        "-json", "-o", json_file,  # also write JSON
        "-threads", CONFIG.get("threads", "10"),
        "-timeout", CONFIG.get("timeout", "10"),
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-tech-detect",
        "-title",
        "-web-server",
        "-content-type",
        "-response-time",
        "-cdn",
        "-ports", CONFIG.get("ports", "80,443,8080,8443,8888,3000,9090"),
    ]

    # Add TLS probe for HTTPS info
    cmd.extend(["-tls-grab", "-tls-probe"])

    run_cmd(cmd, silent=False)

    # Parse JSON output and build tech map
    tech_map = {}
    live_urls = []

    if Path(json_file).exists():
        for line in Path(json_file).read_text().splitlines():
            try:
                entry = json.loads(line.strip())
                url   = entry.get("url", "")
                if not url:
                    continue

                live_urls.append(url)

                host_entry = {
                    "url":          url,
                    "host":         entry.get("host", ""),
                    "status_code":  entry.get("status_code", 0),
                    "title":        entry.get("title", ""),
                    "web_server":   entry.get("webserver", ""),
                    "tech":         entry.get("tech", []),
                    "content_type": entry.get("content_type", ""),
                    "response_ms":  entry.get("time", ""),
                    "is_cdn":       entry.get("cdn", False),
                    "tls":          entry.get("tls", {}),
                    "redirect":     entry.get("final_url", ""),
                }
                tech_map[url] = host_entry

                # Save to DB as asset
                db = FindingsDB()
                db.add_asset(
                    scan_id=scan_id,
                    asset_type="url",
                    value=url,
                    is_live=True,
                    tech_stack={
                        "tech":   entry.get("tech", []),
                        "server": entry.get("webserver", ""),
                        "title":  entry.get("title", ""),
                    }
                )

            except json.JSONDecodeError:
                continue

    # Write clean live URLs file
    write_targets_file(live_file, live_urls)

    status(f"Live hosts: {len(live_urls)}", "ok")

    # Save tech map
    tech_map_file = str(recon_dir / "tech_map.json")
    Path(tech_map_file).write_text(json.dumps(tech_map, indent=2))

    # WAF detection
    if CONFIG.get("waf_detection", "true") == "true" and live_urls:
        waf_map = _detect_wafs(live_urls[:50])  # sample first 50
        waf_file = str(recon_dir / "waf_map.json")
        Path(waf_file).write_text(json.dumps(waf_map, indent=2))

        waf_count = sum(1 for v in waf_map.values() if v.get("waf"))
        if waf_count:
            status(f"WAF detected on {waf_count} hosts — scan will auto-throttle", "warn")

    # Screenshot live hosts
    if CONFIG.get("auto_screenshot", "true") == "true" and tool_exists("gowitness"):
        _take_screenshots(live_file, workdir, scan_id)

    return live_file, tech_map_file


def _detect_wafs(urls: List[str]) -> Dict[str, dict]:
    """
    Use wafw00f to detect WAF/CDN presence.
    Returns {url: {waf: str, confidence: int}}
    """
    if not tool_exists("wafw00f"):
        return {}

    waf_map = {}
    # Batch check - wafw00f supports multiple URLs
    rc, stdout, _ = run_cmd(
        ["wafw00f"] + urls[:20] + ["-o", "/tmp/waf_results.json", "-f", "json"],
        silent=True, timeout=60
    )

    try:
        if Path("/tmp/waf_results.json").exists():
            data = json.loads(Path("/tmp/waf_results.json").read_text())
            for entry in data:
                url = entry.get("url", "")
                waf = entry.get("detected", "")
                waf_map[url] = {
                    "waf": waf,
                    "confidence": 90 if waf else 0,
                }
    except Exception:
        pass

    return waf_map


def _take_screenshots(live_file: str, workdir: Path, scan_id: str) -> None:
    """Take screenshots of all live URLs using gowitness."""
    screenshot_dir = workdir / "screenshots"
    screenshot_dir.mkdir(exist_ok=True)

    status("Taking screenshots (gowitness)...", "run")
    run_cmd(
        [
            "gowitness", "file",
            "-f", live_file,
            "--destination", str(screenshot_dir),
            "--timeout", "10",
            "--threads", "4",
            "--disable-logging",
        ],
        silent=True, timeout=600
    )

    count = len(list(screenshot_dir.glob("*.png")))
    status(f"Screenshots: {count} captured", "ok")


def load_tech_map(workdir: str) -> dict:
    """Load tech map from workdir for use by other modules."""
    tech_file = Path(workdir) / "recon" / "tech_map.json"
    if tech_file.exists():
        try:
            return json.loads(tech_file.read_text())
        except Exception:
            return {}
    return {}


def load_waf_map(workdir: str) -> dict:
    """Load WAF map. Used by pentest engine to adapt throttling."""
    waf_file = Path(workdir) / "recon" / "waf_map.json"
    if waf_file.exists():
        try:
            return json.loads(waf_file.read_text())
        except Exception:
            return {}
    return {}


def get_cms_targets(tech_map: dict, cms: str) -> list:
    """
    Filter tech_map for hosts running a specific CMS/technology.
    e.g. get_cms_targets(tech_map, "wordpress") → [url1, url2, ...]
    """
    cms_lower = cms.lower()
    results   = []
    for url, info in tech_map.items():
        tech_list = [t.lower() for t in info.get("tech", [])]
        if any(cms_lower in t for t in tech_list):
            results.append(url)
    return results
