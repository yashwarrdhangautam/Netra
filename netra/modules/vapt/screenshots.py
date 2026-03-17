"""
netra/modules/vapt/screenshots.py
Web page screenshot capture using Playwright headless browser.

For every live URL discovered during recon, captures a full-page screenshot
and saves it to scan_dir/screenshots/. Thumbnails are generated for the HTML
report. Falls back gracefully if Playwright is not installed.

Install:  pip install playwright && playwright install chromium
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from netra.core.utils import status, run_cmd

logger = logging.getLogger("netra.modules.vapt.screenshots")

SCREENSHOT_TIMEOUT  = 15_000   # ms per page
MAX_SCREENSHOTS     = 100      # hard cap per scan
VIEWPORT_WIDTH      = 1280
VIEWPORT_HEIGHT     = 900
THUMBNAIL_WIDTH     = 320


def _slug(url: str) -> str:
    """Convert a URL to a safe filename slug."""
    slug = re.sub(r"https?://", "", url)
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", slug)
    return slug[:80]


def is_playwright_available() -> bool:
    """Return True if Playwright is installed and chromium is available."""
    try:
        import playwright  # noqa: F401
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


async def _capture_single(page, url: str, out_dir: Path) -> Optional[dict]:
    """
    Capture a single URL screenshot asynchronously.

    Args:
        page:    Playwright Page object.
        url:     Target URL.
        out_dir: Directory to save screenshot.

    Returns:
        Dict with url, path, title, timestamp — or None on failure.
    """
    slug     = _slug(url)
    png_path = out_dir / f"{slug}.png"
    thumb    = out_dir / f"{slug}_thumb.png"

    try:
        await page.goto(url, timeout=SCREENSHOT_TIMEOUT, wait_until="networkidle")
        title = await page.title()
        await page.screenshot(
            path=str(png_path),
            full_page=True,
        )

        # Generate thumbnail via Playwright viewport
        await page.set_viewport_size({"width": THUMBNAIL_WIDTH, "height": 200})
        await page.screenshot(path=str(thumb), clip={"x": 0, "y": 0,
                                                      "width": THUMBNAIL_WIDTH,
                                                      "height": 200})

        logger.debug("Screenshot: %s → %s", url, png_path.name)
        return {
            "url":       url,
            "path":      str(png_path),
            "thumb":     str(thumb),
            "title":     title,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.debug("Screenshot failed for %s: %s", url, e)
        return None


async def _capture_all_async(
    urls: List[str],
    out_dir: Path,
    concurrency: int = 3,
) -> List[dict]:
    """
    Capture screenshots for all URLs using concurrent browser contexts.

    Args:
        urls:        List of URLs to screenshot.
        out_dir:     Output directory.
        concurrency: Number of parallel browser pages.

    Returns:
        List of screenshot result dicts.
    """
    from playwright.async_api import async_playwright

    results  = []
    sem      = asyncio.Semaphore(concurrency)
    out_dir.mkdir(parents=True, exist_ok=True)

    async def capture_with_sem(browser, url: str) -> Optional[dict]:
        """Capture screenshot with semaphore limit."""
        async with sem:
            ctx  = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (compatible; NETRA-Scanner/1.0)",
            )
            page = await ctx.new_page()
            try:
                return await _capture_single(page, url, out_dir)
            finally:
                await ctx.close()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        tasks   = [capture_with_sem(browser, url) for url in urls]
        raw     = await asyncio.gather(*tasks, return_exceptions=True)
        await browser.close()

    results = [r for r in raw if isinstance(r, dict)]
    return results


def capture_screenshots(
    urls: List[str],
    scan_dir: Path,
    max_count: int = MAX_SCREENSHOTS,
) -> List[dict]:
    """
    Main entry point: capture screenshots for discovered URLs.

    Args:
        urls:      Live URLs from HTTP discovery phase.
        scan_dir:  Scan working directory (screenshots/ subdirectory used).
        max_count: Maximum screenshots per scan.

    Returns:
        List of dicts with url, path, thumb, title, timestamp.
    """
    if not urls:
        return []

    if not is_playwright_available():
        status(
            "Playwright not installed — skipping screenshots. "
            "Install: pip install playwright && playwright install chromium",
            "warn",
        )
        return []

    out_dir    = scan_dir / "screenshots"
    target_urls = urls[:max_count]

    status(f"Capturing {len(target_urls)} screenshots (max {max_count})...", "info")

    try:
        results = asyncio.run(_capture_all_async(target_urls, out_dir))
        status(f"Screenshots captured: {len(results)}/{len(target_urls)}", "ok")
        return results
    except Exception as e:
        logger.error("Screenshot capture failed: %s", e)
        status(f"Screenshot capture error: {e}", "warn")
        return []


def screenshots_to_findings(
    screenshots: List[dict],
    scan_id: str,
) -> List[dict]:
    """
    Convert screenshot metadata into lightweight info findings for the DB.

    Args:
        screenshots: Results from capture_screenshots().
        scan_id:     Current scan ID.

    Returns:
        List of finding dicts representing discovered web pages.
    """
    findings = []
    for s in screenshots:
        findings.append({
            "scan_id":     scan_id,
            "title":       f"Web page: {s.get('title') or s['url']}",
            "severity":    "info",
            "category":    "web_discovery",
            "host":        s["url"],
            "url":         s["url"],
            "description": f"Live web page discovered. Screenshot saved.",
            "evidence":    s["path"],
            "timestamp":   s["timestamp"],
        })
    return findings
