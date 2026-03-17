"""
netra/core/utils.py
Shared utilities used across all modules.
run_cmd()    — the single function for executing all external tools
banner()     — consistent section headers in terminal
color()      — terminal color codes
risk_label() — severity → color/emoji
"""

import os
import re
import sys
import time
import shutil
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple


# ── Terminal colors ───────────────────────────────────────────────────
class C:
    """ANSI terminal color codes."""

    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    TEAL   = "\033[96m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    CLEAR  = "\033[2J\033[H"


SEV_COLOR = {
    "critical": C.RED,
    "high":     C.ORANGE,
    "medium":   C.YELLOW,
    "low":      C.GREEN,
    "info":     C.DIM,
}

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}


def banner(title: str, subtitle: str = "", color: str = C.TEAL) -> None:
    """Print a consistent section banner."""
    width = 62
    print(f"\n{color}{'═' * width}{C.RESET}")
    print(f"{color}  {title.upper()}{C.RESET}")
    if subtitle:
        print(f"{C.DIM}  {subtitle}{C.RESET}")
    print(f"{color}{'─' * width}{C.RESET}")


def status(msg: str, level: str = "info") -> None:
    """Print a status line with consistent formatting."""
    icons = {
        "info":    f"{C.DIM}[·]{C.RESET}",
        "ok":      f"{C.GREEN}[✓]{C.RESET}",
        "warn":    f"{C.YELLOW}[!]{C.RESET}",
        "error":   f"{C.RED}[✗]{C.RESET}",
        "run":     f"{C.TEAL}[>]{C.RESET}",
        "finding": f"{C.RED}[F]{C.RESET}",
        "skip":    f"{C.DIM}[-]{C.RESET}",
        "ai":      f"{C.PURPLE}[A]{C.RESET}",
    }
    icon = icons.get(level, icons["info"])
    print(f"  {icon} {msg}")


def run_cmd(
    cmd: list,
    output_file: str = None,
    timeout: int = None,
    silent: bool = False,
    env: dict = None,
) -> Tuple[int, str, str]:
    """
    Execute an external command. The single function used for all tool calls.

    Args:
        cmd:         Command as list: ["nmap", "-sV", "10.0.0.1"]
        output_file: If set, write stdout to this file
        timeout:     Max seconds (None = no limit)
        silent:      If True, suppress live output
        env:         Extra environment variables

    Returns:
        (returncode, stdout, stderr)
    """
    from netra.core.config import CONFIG

    if timeout is None:
        timeout = int(CONFIG.get("timeout", 10)) * 60  # config timeout in minutes

    cmd_env = os.environ.copy()
    if env:
        cmd_env.update(env)

    tool = cmd[0]
    if not silent:
        status(f"Running: {' '.join(str(c) for c in cmd[:6])}", "run")

    start = time.time()
    stdout_lines: list = []
    stderr_lines: list = []

    try:
        proc = subprocess.Popen(
            [str(c) for c in cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=cmd_env,
        )

        out_file = None
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            out_file = open(output_file, "w")

        try:
            for line in proc.stdout:
                stdout_lines.append(line)
                if out_file:
                    out_file.write(line)
                    out_file.flush()
                if not silent and line.strip():
                    if any(k in line.lower() for k in
                           ["critical", "high", "found", "open", "error",
                            "[+]", "[!]", "cve-", "vulnerable"]):
                        print(f"    {C.DIM}{line.rstrip()}{C.RESET}")
            stderr_lines = proc.stderr.readlines()
        finally:
            if out_file:
                out_file.close()

        proc.wait(timeout=timeout)
        elapsed = time.time() - start

        stdout = "".join(stdout_lines)
        stderr = "".join(stderr_lines)

        if not silent:
            elapsed_str = f"{elapsed:.1f}s"
            if proc.returncode == 0:
                status(f"{tool} done in {elapsed_str}", "ok")
            else:
                status(f"{tool} exited {proc.returncode} in {elapsed_str}", "warn")

        return proc.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        proc.kill()
        status(f"{tool} timed out after {timeout}s", "warn")
        return -1, "".join(stdout_lines), "TIMEOUT"

    except FileNotFoundError:
        status(f"{tool} not found — run: python3 netra.py --install-deps", "error")
        return -2, "", f"{tool} not found"

    except Exception as e:
        status(f"{tool} error: {e}", "error")
        return -3, "", str(e)


def tool_exists(name: str) -> bool:
    """Check if a tool is in PATH."""
    return shutil.which(name) is not None


def is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_ip(value: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    """Loose check if a value looks like a domain."""
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
    return bool(re.match(pattern, value.strip()))


def is_url(value: str) -> bool:
    """Check if a value is an HTTP/HTTPS URL."""
    return value.strip().startswith(("http://", "https://"))


def extract_domain(url: str) -> str:
    """Extract base domain from a URL."""
    url = url.strip()
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0].split(":")[0].split("?")[0]
    return url.lower()


def deduplicate(items: list) -> list:
    """Deduplicate list while preserving order."""
    seen: set = set()
    out: list = []
    for item in items:
        k = item.strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(item.strip())
    return out


def make_workdir(output_dir: str, label: str = "") -> Path:
    """
    Create a structured per-scan working directory under ~/.netra/data/scans/.

    Layout:
        scan_YYYYMMDD_HHMMSS_<label>/
        ├── reports/        ← All generated reports
        ├── screenshots/    ← Web page screenshots
        ├── raw/            ← Raw tool output (nmap.xml, nuclei.json, etc.)
        ├── logs/           ← Per-tool logs
        ├── recon/          ← Recon phase data
        ├── pentest/        ← Pentest phase data
        └── checkpoint.json ← Resume point
    """
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", label.lower())[:30] if label else ""
    name = f"scan_{ts}_{slug}" if slug else f"scan_{ts}"
    path = Path(output_dir) / name
    path.mkdir(parents=True, exist_ok=True)

    for sub in ["reports", "screenshots", "raw", "logs",
                "recon", "pentest", "auth_session", "evidence"]:
        (path / sub).mkdir(exist_ok=True)

    return path


def read_targets_file(path: str) -> list:
    """Read a flat text file of targets (one per line). Strips comments."""
    targets: list = []
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    except Exception as e:
        status(f"Cannot read {path}: {e}", "error")
    return targets


def write_targets_file(path: str, targets: list) -> None:
    """Write a list of targets to a flat text file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(targets) + "\n")


def count_lines(path: str) -> int:
    """Count non-empty lines in a file."""
    try:
        return sum(1 for line in Path(path).read_text().splitlines() if line.strip())
    except Exception:
        return 0


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate string for storage in DB."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [truncated {len(text) - max_len} chars]"


def severity_sort_key(sev: str) -> int:
    """Return sort key for severity string (lower = more severe)."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)


def format_table(rows: list, headers: list, col_widths: list = None) -> str:
    """Simple ASCII table formatter."""
    if not rows:
        return "  (no data)"
    if not col_widths:
        col_widths = [
            max(len(str(r[i])) for r in [headers] + rows) + 2
            for i in range(len(headers))
        ]
    sep = "+" + "+".join("-" * w for w in col_widths) + "+"

    def fmt_row(r: list) -> str:
        """Format a single table row with fixed column widths."""
        return "|" + "|".join(
            f" {str(c):<{w - 2}} " for c, w in zip(r, col_widths)
        ) + "|"

    lines = [sep, fmt_row(headers), sep]
    for row in rows:
        lines.append(fmt_row(row))
    lines.append(sep)
    return "\n".join(lines)


def print_finding(finding: dict) -> None:
    """Print a single finding to terminal in a readable format."""
    sev   = finding.get("severity", "info").lower()
    color = SEV_COLOR.get(sev, C.DIM)
    emoji = SEV_EMOJI.get(sev, "⚪")

    print(f"\n  {color}{'─' * 58}{C.RESET}")
    print(f"  {emoji} {color}{C.BOLD}{sev.upper()}{C.RESET}  {finding.get('title', '?')}")
    print(f"  {C.DIM}Host:{C.RESET}  {finding.get('host', '?')}")
    if finding.get("url"):
        print(f"  {C.DIM}URL:{C.RESET}   {finding.get('url')}")
    if finding.get("cvss_score"):
        print(f"  {C.DIM}CVSS:{C.RESET}  {finding.get('cvss_score')} — {finding.get('cvss_vector', '')}")
    if finding.get("cve_id"):
        print(f"  {C.DIM}CVE:{C.RESET}   {finding.get('cve_id')}")
    if finding.get("description"):
        desc = finding.get("description", "")[:120]
        print(f"  {C.DIM}Desc:{C.RESET}  {desc}")
    print(f"  {color}{'─' * 58}{C.RESET}")
