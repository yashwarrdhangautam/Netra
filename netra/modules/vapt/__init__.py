"""
netra/modules/vapt
Vulnerability Assessment and Penetration Testing module.
Wraps recon, pentest, cloud detection, and screenshot capture
under the NETRA package.
"""

from netra.modules.vapt.screenshots import (
    capture_screenshots,
    screenshots_to_findings,
    is_playwright_available,
)
from netra.modules.vapt.cloud_detect import (
    detect_cloud,
    cloud_to_findings,
    prompt_cspm,
)

__all__ = [
    # Screenshots
    "capture_screenshots",
    "screenshots_to_findings",
    "is_playwright_available",
    # Cloud detection
    "detect_cloud",
    "cloud_to_findings",
    "prompt_cspm",
]
