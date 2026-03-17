"""
netra/core/deps.py
Smart dependency manager for NETRA.

Checks PATH first, then ~/.netra/tools/bin/.
Downloads missing tools locally (no sudo needed).
Supports: go-install, apt, brew, direct binary download.
"""

import os
import sys
import shutil
import subprocess
import platform
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netra.core.deps")

# ── Tool registry ──────────────────────────────────────────────────────────────
TOOLS: Dict[str, dict] = {
    # ── Recon ──────────────────────────────────────────────────────────────────
    "subfinder": {
        "check":    ["subfinder", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "required": True,
        "category": "recon",
    },
    "amass": {
        "check":    ["amass", "version"],
        "method":   "go",
        "install":  "github.com/owasp-amass/amass/v4/...@master",
        "required": False,
        "category": "recon",
    },
    "dnsx": {
        "check":    ["dnsx", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "required": True,
        "category": "recon",
    },
    "httpx": {
        "check":    ["httpx", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "required": True,
        "category": "recon",
    },
    "assetfinder": {
        "check":    ["assetfinder", "--help"],
        "method":   "go",
        "install":  "github.com/tomnomnom/assetfinder@latest",
        "required": False,
        "category": "recon",
    },
    # ── Scanning ───────────────────────────────────────────────────────────────
    "nmap": {
        "check":    ["nmap", "--version"],
        "method":   "system",
        "install":  "nmap",
        "required": True,
        "category": "scanning",
    },
    "naabu": {
        "check":    ["naabu", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "required": True,
        "category": "scanning",
    },
    "nuclei": {
        "check":    ["nuclei", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "required": True,
        "category": "scanning",
    },
    "nikto": {
        "check":    ["nikto", "-Version"],
        "method":   "system",
        "install":  "nikto",
        "required": False,
        "category": "scanning",
    },
    # ── Pentest ────────────────────────────────────────────────────────────────
    "sqlmap": {
        "check":    ["sqlmap", "--version"],
        "method":   "pip",
        "install":  "sqlmap",
        "required": False,
        "category": "pentest",
    },
    "ffuf": {
        "check":    ["ffuf", "-V"],
        "method":   "go",
        "install":  "github.com/ffuf/ffuf/v2@latest",
        "required": False,
        "category": "pentest",
    },
    "gobuster": {
        "check":    ["gobuster", "version"],
        "method":   "go",
        "install":  "github.com/OJ/gobuster/v3@latest",
        "required": False,
        "category": "pentest",
    },
    # ── Screenshots ────────────────────────────────────────────────────────────
    "gowitness": {
        "check":    ["gowitness", "version"],
        "method":   "go",
        "install":  "github.com/sensepost/gowitness@latest",
        "required": False,
        "category": "screenshots",
    },
    # ── Subdomain tools ────────────────────────────────────────────────────────
    "subzy": {
        "check":    ["subzy", "version"],
        "method":   "go",
        "install":  "github.com/LukaSikic/subzy@latest",
        "required": False,
        "category": "recon",
    },
    "gau": {
        "check":    ["gau", "--version"],
        "method":   "go",
        "install":  "github.com/lc/gau/v2/cmd/gau@latest",
        "required": False,
        "category": "recon",
    },
    "katana": {
        "check":    ["katana", "-version"],
        "method":   "go",
        "install":  "github.com/projectdiscovery/katana/cmd/katana@latest",
        "required": False,
        "category": "recon",
    },
}

SEVERITY_COLORS = {
    "ok":      "\033[92m",   # green
    "warn":    "\033[93m",   # yellow
    "error":   "\033[91m",   # red
    "info":    "\033[94m",   # blue
    "reset":   "\033[0m",
    "bold":    "\033[1m",
}


def _netra_tools_dir() -> Path:
    """Return the local NETRA tools directory, creating it if needed."""
    tools_dir = Path(os.environ.get("NETRA_TOOLS_DIR", Path.home() / ".netra" / "tools" / "bin"))
    tools_dir.mkdir(parents=True, exist_ok=True)
    return tools_dir


def _is_available(tool_name: str, check_cmd: List[str]) -> Tuple[bool, str]:
    """
    Check if a tool is available in PATH or ~/.netra/tools/bin.

    Args:
        tool_name: Name of the tool binary.
        check_cmd: Command list to run to verify installation.

    Returns:
        Tuple of (available: bool, location: str)
    """
    tools_dir = _netra_tools_dir()

    # Check PATH first
    path_loc = shutil.which(tool_name)
    if path_loc:
        try:
            subprocess.run(check_cmd, capture_output=True, timeout=5)
            return True, path_loc
        except Exception:
            pass

    # Check local NETRA tools dir
    local_bin = tools_dir / tool_name
    if local_bin.exists():
        try:
            subprocess.run([str(local_bin)] + check_cmd[1:], capture_output=True, timeout=5)
            return True, str(local_bin)
        except Exception:
            pass

    return False, ""


def _install_go_tool(pkg_path: str, tool_name: str) -> bool:
    """
    Install a Go tool into ~/.netra/tools/bin/.

    Args:
        pkg_path: Go package path (e.g. github.com/org/tool@latest)
        tool_name: Binary name of the tool.

    Returns:
        True if installation succeeded.
    """
    tools_dir = _netra_tools_dir()
    env = os.environ.copy()
    env["GOBIN"] = str(tools_dir)

    if not shutil.which("go"):
        logger.warning("Go not found — cannot install %s", tool_name)
        return False

    try:
        result = subprocess.run(
            ["go", "install", "-v", pkg_path],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode == 0 and (tools_dir / tool_name).exists()
    except Exception as e:
        logger.error("Failed to install %s: %s", tool_name, e)
        return False


def _install_system_tool(pkg_name: str) -> bool:
    """
    Install a system package via apt-get, brew, or dnf.

    Args:
        pkg_name: Package name to install.

    Returns:
        True if installation succeeded.
    """
    system = platform.system().lower()

    if system == "linux":
        for pm in [["apt-get", "install", "-y"], ["dnf", "install", "-y"], ["pacman", "-S", "--noconfirm"]]:
            if shutil.which(pm[0]):
                try:
                    result = subprocess.run(
                        ["sudo"] + pm + [pkg_name],
                        capture_output=True, text=True, timeout=120
                    )
                    return result.returncode == 0
                except Exception:
                    continue
    elif system == "darwin":
        if shutil.which("brew"):
            try:
                result = subprocess.run(
                    ["brew", "install", pkg_name],
                    capture_output=True, text=True, timeout=180
                )
                return result.returncode == 0
            except Exception:
                pass

    return False


def _install_pip_tool(pkg_name: str) -> bool:
    """
    Install a Python package tool via pip.

    Args:
        pkg_name: PyPI package name.

    Returns:
        True if installation succeeded.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg_name, "--break-system-packages"],
            capture_output=True, text=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


def check_deps(verbose: bool = True) -> Dict[str, dict]:
    """
    Check all tools for availability. Returns status dict.

    Args:
        verbose: Print status table to stdout.

    Returns:
        Dict mapping tool name to {available, location, category, required}
    """
    C = SEVERITY_COLORS
    results = {}

    if verbose:
        print(f"\n{C['bold']}NETRA — Dependency Status{C['reset']}")
        print("─" * 60)
        header = f"  {'Tool':<16} {'Status':<12} {'Category':<12} {'Location'}"
        print(header)
        print("─" * 60)

    for name, meta in TOOLS.items():
        available, location = _is_available(name, meta["check"])
        results[name] = {
            "available": available,
            "location":  location,
            "category":  meta["category"],
            "required":  meta["required"],
        }

        if verbose:
            if available:
                status_str = f"{C['ok']}✓ found{C['reset']}"
                loc_str    = location[:45] if location else ""
            elif meta["required"]:
                status_str = f"{C['error']}✗ missing{C['reset']}"
                loc_str    = "Run: python3 netra.py --install-deps"
            else:
                status_str = f"{C['warn']}○ optional{C['reset']}"
                loc_str    = ""

            print(f"  {name:<16} {status_str:<22} {meta['category']:<12} {loc_str}")

    if verbose:
        print("─" * 60)
        total    = len(results)
        found    = sum(1 for v in results.values() if v["available"])
        missing  = sum(1 for v in results.values() if not v["available"] and v["required"])
        optional = sum(1 for v in results.values() if not v["available"] and not v["required"])
        print(f"  {C['bold']}Total: {total}  Found: {C['ok']}{found}{C['reset']}"
              f"  Missing-required: {C['error']}{missing}{C['reset']}"
              f"  Optional-missing: {C['warn']}{optional}{C['reset']}")
        print()

    return results


def install_deps(tools_filter: Optional[List[str]] = None) -> None:
    """
    Install all missing tools into ~/.netra/tools/bin/.

    Args:
        tools_filter: Optional list of tool names to install (default: all missing).
    """
    C = SEVERITY_COLORS
    tools_dir = _netra_tools_dir()

    print(f"\n{C['bold']}NETRA — Installing Tools → {tools_dir}{C['reset']}")
    print("─" * 60)

    target_tools = {
        k: v for k, v in TOOLS.items()
        if (tools_filter is None or k in tools_filter)
    }

    installed = 0
    failed    = []

    for name, meta in target_tools.items():
        available, _ = _is_available(name, meta["check"])
        if available:
            print(f"  {C['ok']}✓{C['reset']} {name:<18} already installed")
            continue

        print(f"  {C['info']}↓{C['reset']} {name:<18} installing...", end="", flush=True)

        ok = False
        method = meta["method"]

        if method == "go":
            ok = _install_go_tool(meta["install"], name)
        elif method == "system":
            ok = _install_system_tool(meta["install"])
        elif method == "pip":
            ok = _install_pip_tool(meta["install"])

        if ok:
            print(f"\r  {C['ok']}✓{C['reset']} {name:<18} installed")
            installed += 1
        else:
            print(f"\r  {C['error']}✗{C['reset']} {name:<18} failed")
            failed.append(name)

    print("─" * 60)
    print(f"  Installed: {C['ok']}{installed}{C['reset']}  "
          f"Failed: {C['error']}{len(failed)}{C['reset']}")

    if failed:
        print(f"\n  Failed tools: {', '.join(failed)}")
        print(f"  Try manually: go install github.com/... or apt-get install ...")

    # Update nuclei templates if nuclei was installed
    nuclei_ok, _ = _is_available("nuclei", ["nuclei", "-version"])
    if nuclei_ok:
        _update_nuclei_templates()

    print()


def _update_nuclei_templates() -> None:
    """Download/update nuclei vulnerability templates."""
    C = SEVERITY_COLORS
    templates_dir = Path.home() / ".netra" / "tools" / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)

    print(f"  {C['info']}↓{C['reset']} nuclei-templates   updating...")
    try:
        subprocess.run(
            ["nuclei", "-update-templates", "-templates-directory", str(templates_dir)],
            capture_output=True, timeout=120
        )
        print(f"  {C['ok']}✓{C['reset']} nuclei-templates   updated → {templates_dir}")
    except Exception as e:
        logger.warning("nuclei template update failed: %s", e)


def quick_check() -> bool:
    """
    Quick check — returns True if all required tools are available.
    Used at scan startup.

    Returns:
        True if all required tools present.
    """
    for name, meta in TOOLS.items():
        if not meta["required"]:
            continue
        available, _ = _is_available(name, meta["check"])
        if not available:
            print(f"\033[93m[WARN]\033[0m Required tool missing: {name}")
            print(f"       Run: python3 netra.py --install-deps")
            return False
    return True
