"""Database seed script — populate NETRA with initial compliance mappings and profiles."""
import asyncio
import sys
from pathlib import Path
from typing import Any

import click

# Ensure project root is on sys.path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


async def _seed_compliance_mappings() -> int:
    """Load CWE → framework mappings into the database.

    Returns:
        Number of mapping records created.
    """
    from netra.db.seeds.compliance_mappings import CWE_COMPLIANCE_MAP
    from netra.db.session import async_session_factory

    count = 0
    async with async_session_factory() as session:
        for cwe_id, frameworks in CWE_COMPLIANCE_MAP.items():
            for framework, control_ids in frameworks.items():
                for control_id in control_ids:
                    from netra.db.models.compliance import ComplianceMapping

                    mapping = ComplianceMapping(
                        cwe_id=cwe_id,
                        framework=framework,
                        control_id=control_id,
                        control_name=f"{framework.upper()} {control_id}",
                        control_description="",
                        status="not_assessed",
                        is_mapped=True,
                    )
                    session.add(mapping)
                    count += 1
        await session.commit()
    return count


async def _seed_scan_profiles() -> int:
    """Seed default scan profile configurations.

    Returns:
        Number of profiles seeded.
    """
    profiles: list[dict[str, Any]] = [
        {
            "name": "quick",
            "label": "Quick Recon",
            "description": "Fast subdomain + port discovery, critical-only nuclei",
            "tools": ["subfinder", "httpx", "nuclei"],
            "nuclei_severity": ["critical"],
            "timeout_minutes": 15,
        },
        {
            "name": "standard",
            "label": "Standard Scan",
            "description": "Full recon + vulnerability scanning, all nuclei templates",
            "tools": ["subfinder", "httpx", "nuclei", "nmap", "ffuf"],
            "nuclei_severity": ["critical", "high", "medium"],
            "timeout_minutes": 60,
        },
        {
            "name": "deep",
            "label": "Deep Pentest",
            "description": "All tools including SQLMap, Dalfox, Nikto + AI analysis",
            "tools": [
                "subfinder", "httpx", "nuclei", "nmap", "ffuf",
                "sqlmap", "dalfox", "nikto", "amass",
            ],
            "nuclei_severity": ["critical", "high", "medium", "low"],
            "timeout_minutes": 180,
        },
        {
            "name": "api_only",
            "label": "API Security",
            "description": "OWASP API Top 10 focused — endpoint fuzzing + auth testing",
            "tools": ["httpx", "nuclei", "ffuf", "dalfox"],
            "nuclei_severity": ["critical", "high", "medium"],
            "timeout_minutes": 45,
        },
        {
            "name": "cloud",
            "label": "Cloud Security",
            "description": "AWS/GCP/Azure posture — Prowler, Trivy, Checkov",
            "tools": ["prowler", "trivy", "checkov"],
            "nuclei_severity": [],
            "timeout_minutes": 90,
        },
        {
            "name": "container",
            "label": "Container Scan",
            "description": "Docker image + Kubernetes manifest scanning",
            "tools": ["trivy", "checkov", "semgrep"],
            "nuclei_severity": [],
            "timeout_minutes": 30,
        },
        {
            "name": "ai_llm",
            "label": "LLM Security",
            "description": "Prompt injection, jailbreak, PII leak testing",
            "tools": ["llm_security"],
            "nuclei_severity": [],
            "timeout_minutes": 30,
        },
    ]

    # Store as JSON config file (no DB model for profiles yet)
    import json

    config_dir = Path.home() / ".netra" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    profiles_path = config_dir / "scan_profiles.json"
    profiles_path.write_text(json.dumps(profiles, indent=2))
    return len(profiles)


async def _seed_owasp_mappings() -> int:
    """Seed OWASP Top 10 2021 → CWE mappings as a quick-reference config.

    Returns:
        Number of OWASP categories seeded.
    """
    import json

    owasp_top_10: dict[str, dict[str, Any]] = {
        "A01:2021": {
            "name": "Broken Access Control",
            "cwes": ["CWE-200", "CWE-201", "CWE-352", "CWE-639", "CWE-862", "CWE-863"],
        },
        "A02:2021": {
            "name": "Cryptographic Failures",
            "cwes": ["CWE-259", "CWE-327", "CWE-331", "CWE-328"],
        },
        "A03:2021": {
            "name": "Injection",
            "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-77", "CWE-94"],
        },
        "A04:2021": {
            "name": "Insecure Design",
            "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        },
        "A05:2021": {
            "name": "Security Misconfiguration",
            "cwes": ["CWE-16", "CWE-611", "CWE-614", "CWE-756"],
        },
        "A06:2021": {
            "name": "Vulnerable and Outdated Components",
            "cwes": ["CWE-1104"],
        },
        "A07:2021": {
            "name": "Identification and Authentication Failures",
            "cwes": ["CWE-287", "CWE-384", "CWE-613", "CWE-798"],
        },
        "A08:2021": {
            "name": "Software and Data Integrity Failures",
            "cwes": ["CWE-345", "CWE-502", "CWE-829"],
        },
        "A09:2021": {
            "name": "Security Logging and Monitoring Failures",
            "cwes": ["CWE-778"],
        },
        "A10:2021": {
            "name": "Server-Side Request Forgery (SSRF)",
            "cwes": ["CWE-918"],
        },
    }

    config_dir = Path.home() / ".netra" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    owasp_path = config_dir / "owasp_top10_2021.json"
    owasp_path.write_text(json.dumps(owasp_top_10, indent=2))
    return len(owasp_top_10)


@click.command()
@click.option("--owasp", is_flag=True, help="Seed OWASP Top 10 mappings")
@click.option("--profiles", is_flag=True, help="Seed scan profiles")
@click.option("--compliance", is_flag=True, help="Seed CWE compliance mappings into DB")
@click.option("--all", "seed_all", is_flag=True, help="Seed all data")
def main(owasp: bool, profiles: bool, compliance: bool, seed_all: bool) -> None:
    """Seed the database with initial data.

    Args:
        owasp: Seed OWASP Top 10 mappings
        profiles: Seed scan profiles
        compliance: Seed CWE-to-framework compliance mappings
        seed_all: Seed all data
    """
    if seed_all:
        owasp = True
        profiles = True
        compliance = True

    if not any([owasp, profiles, compliance]):
        click.echo("No seed option selected. Use --all to seed everything.")
        click.echo("Options: --owasp, --profiles, --compliance, --all")
        return

    click.echo("NETRA Database Seeder")
    click.echo("=" * 40)

    if owasp:
        count = asyncio.run(_seed_owasp_mappings())
        click.echo(f"  OWASP Top 10 mappings: {count} categories seeded")

    if profiles:
        count = asyncio.run(_seed_scan_profiles())
        click.echo(f"  Scan profiles: {count} profiles seeded")

    if compliance:
        try:
            count = asyncio.run(_seed_compliance_mappings())
            click.echo(f"  Compliance mappings: {count} records created")
        except Exception as exc:
            click.echo(f"  Compliance mappings: FAILED — {exc}")
            click.echo("  (Run 'alembic upgrade head' first to create tables)")

    click.echo("\nDone.")


if __name__ == "__main__":
    main()
