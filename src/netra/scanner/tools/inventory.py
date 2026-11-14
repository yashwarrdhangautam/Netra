"""Which scanner binaries are installed, and which of them a scan actually needs.

The wrappers report a missing binary only as a per-tool failure inside a scan.
This inventory lets the API and GUI show that state before a scan is started.
"""

from __future__ import annotations

from dataclasses import dataclass

from netra.scanner.tools.base import CliTool


@dataclass(frozen=True)
class ToolSpec:
    binary: str
    label: str
    category: str
    optional: bool = False
    install_hint: str = ""


TOOL_SPECS: tuple[ToolSpec, ...] = (
    # Recon and asset discovery
    ToolSpec(
        "subfinder", "subfinder", "recon", install_hint="go install (see docker/Dockerfile.worker)"
    ),
    ToolSpec(
        "amass",
        "amass",
        "recon",
        install_hint="go install github.com/owasp-amass/amass/v4/cmd/amass",
    ),
    ToolSpec(
        "assetfinder",
        "assetfinder",
        "recon",
        install_hint="go install github.com/tomnomnom/assetfinder",
    ),
    ToolSpec(
        "dnsx", "dnsx", "recon", install_hint="go install github.com/projectdiscovery/dnsx/cmd/dnsx"
    ),
    ToolSpec(
        "naabu",
        "naabu",
        "recon",
        install_hint="go install github.com/projectdiscovery/naabu/v2/cmd/naabu",
    ),
    ToolSpec(
        "httpx",
        "httpx",
        "recon",
        install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx",
    ),
    ToolSpec(
        "katana",
        "katana",
        "recon",
        install_hint="go install github.com/projectdiscovery/katana/cmd/katana",
    ),
    ToolSpec("gau", "gau", "recon", install_hint="go install github.com/lc/gau/v2/cmd/gau"),
    ToolSpec("nmap", "nmap", "recon", install_hint="apt install nmap"),
    ToolSpec("shodan", "shodan CLI", "recon", optional=True, install_hint="pip install shodan"),
    ToolSpec(
        "recontool", "Recontool", "recon", optional=True, install_hint="see docs; licence unclear"
    ),
    # Vulnerability checks and fuzzing
    ToolSpec(
        "nuclei",
        "nuclei",
        "vuln",
        install_hint="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
    ),
    ToolSpec("nikto", "nikto", "vuln", install_hint="clone sullo/nikto and link program/nikto.pl"),
    ToolSpec("sqlmap", "sqlmap", "vuln", install_hint="apt install sqlmap"),
    ToolSpec("dalfox", "dalfox", "vuln", install_hint="go install github.com/hahwul/dalfox/v2"),
    ToolSpec("ffuf", "ffuf", "vuln", install_hint="go install github.com/ffuf/ffuf/v2"),
    ToolSpec(
        "wpscan",
        "WPScan",
        "vuln",
        optional=True,
        install_hint="gem install wpscan (needs Ruby build deps)",
    ),
    ToolSpec("subzy", "subzy", "vuln", install_hint="go install github.com/PentestPad/subzy"),
    ToolSpec("garak", "garak", "ai", optional=True, install_hint="pip install garak"),
    # Code, secrets, dependencies and cloud
    ToolSpec(
        "gitleaks", "gitleaks", "code", install_hint="go install github.com/zricethezav/gitleaks/v8"
    ),
    ToolSpec("semgrep", "semgrep", "code", install_hint="pip install semgrep"),
    ToolSpec("pip-audit", "pip-audit", "code", install_hint="pip install pip-audit"),
    ToolSpec("checkov", "checkov", "code", install_hint="pip install checkov"),
    ToolSpec(
        "trivy",
        "Trivy",
        "code",
        optional=True,
        install_hint="install a pinned trivy release binary",
    ),
    ToolSpec("prowler", "Prowler", "cloud", optional=True, install_hint="pip install prowler"),
)


def _resolve(binary: str) -> str | None:
    probe = CliTool()
    probe.binary = binary
    return probe._resolve_binary()


def tool_inventory() -> list[dict[str, object]]:
    """Return installed/missing state for every known scanner binary."""
    rows: list[dict[str, object]] = []
    for spec in TOOL_SPECS:
        path = _resolve(spec.binary)
        rows.append(
            {
                "binary": spec.binary,
                "label": spec.label,
                "category": spec.category,
                "optional": spec.optional,
                "installed": path is not None,
                "path": path,
                "install_hint": spec.install_hint,
            }
        )
    return rows


def missing_required_tools() -> list[str]:
    """Binaries a full scan expects but that are not installed."""
    return [
        row["binary"] for row in tool_inventory() if not row["installed"] and not row["optional"]
    ]
