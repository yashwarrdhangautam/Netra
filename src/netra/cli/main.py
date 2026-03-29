"""NETRA CLI — Interactive menu and command-line interface."""
import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()

BANNER = r"""
[bold blue]
 ███╗   ██╗███████╗████████╗██████╗  █████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║
 ██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold blue]
[dim]The Third Eye of Security — See what others can't.[/dim]
"""


def show_menu() -> None:
    """Display the interactive main menu."""
    console.print(BANNER)
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold yellow", width=6)
    table.add_column()

    table.add_row("[1]", "New Scan")
    table.add_row("[2]", "Resume Scan")
    table.add_row("[3]", "View Findings")
    table.add_row("[4]", "Generate Reports")
    table.add_row("[5]", "Mark False Positive")
    table.add_row("[6]", "Re-test Finding")
    table.add_row("[7]", "Compare Scans")
    table.add_row("[8]", "Open TUI Dashboard")
    table.add_row("[9]", "Settings")
    table.add_row("[0]", "Exit")

    console.print(
        Panel(table, title="[bold]NETRA Menu[/bold]", border_style="blue")
    )

    choice = Prompt.ask(
        "[bold]Select option[/bold]",
        choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        default="1",
    )

    actions = {
        "1": new_scan,
        "2": resume_scan,
        "3": view_findings,
        "4": generate_reports,
        "5": mark_false_positive,
        "6": retest_finding,
        "7": compare_scans,
        "8": open_tui,
        "9": show_settings,
        "0": lambda: sys.exit(0),
    }

    actions[choice]()


def new_scan() -> None:
    """Handle new scan menu option."""
    console.print("[yellow]New Scan — not yet implemented (Phase 1)[/yellow]")


def resume_scan() -> None:
    """Handle resume scan menu option."""
    console.print("[yellow]Resume Scan — not yet implemented (Phase 1)[/yellow]")


def view_findings() -> None:
    """Handle view findings menu option."""
    console.print("[yellow]View Findings — not yet implemented (Phase 1)[/yellow]")


def generate_reports() -> None:
    """Handle generate reports menu option."""
    console.print("[yellow]Generate Reports — not yet implemented (Phase 1)[/yellow]")


def mark_false_positive() -> None:
    """Handle mark false positive menu option."""
    console.print("[yellow]Mark FP — not yet implemented (Phase 1)[/yellow]")


def retest_finding() -> None:
    """Handle retest finding menu option."""
    console.print("[yellow]Re-test — not yet implemented (Phase 1)[/yellow]")


def compare_scans() -> None:
    """Handle compare scans menu option."""
    console.print("[yellow]Compare Scans — not yet implemented (Phase 1)[/yellow]")


def open_tui() -> None:
    """Handle open TUI dashboard menu option."""
    console.print("[yellow]TUI Dashboard — not yet implemented (Phase 3)[/yellow]")


def show_settings() -> None:
    """Handle settings menu option."""
    console.print("[yellow]Settings — not yet implemented (Phase 1)[/yellow]")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="netra",
        description="NETRA — AI-augmented unified cybersecurity platform",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )

    sub = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_parser = sub.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target domain, IP, or file",
    )
    scan_parser.add_argument(
        "--profile",
        "-p",
        default="standard",
        choices=[
            "quick",
            "standard",
            "deep",
            "api_only",
            "cloud",
            "mobile",
            "container",
            "ai_llm",
            "custom",
        ],
        help="Scan profile",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config without scanning",
    )
    scan_parser.add_argument(
        "--output-sarif",
        help="Write SARIF output to this file path",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit code 1 if findings at or above this severity",
    )

    # findings subcommand
    findings_parser = sub.add_parser("findings", help="View findings")
    findings_parser.add_argument("--scan-id", help="Filter by scan ID")
    findings_parser.add_argument("--severity", help="Filter by severity")

    # report subcommand
    report_parser = sub.add_parser("report", help="Generate a report")
    report_parser.add_argument("--type", required=True, help="Report type")
    report_parser.add_argument("--scan-id", required=True, help="Scan ID")

    # diff subcommand
    diff_parser = sub.add_parser("diff", help="Compare two scans")
    diff_parser.add_argument("scan_a", help="First scan ID")
    diff_parser.add_argument("scan_b", help="Second scan ID")

    # server subcommand
    sub.add_parser("server", help="Start the FastAPI server")

    return parser.parse_args()


def get_version() -> str:
    """Get the NETRA version.

    Returns:
        Version string
    """
    from netra import __version__

    return __version__


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.command is None:
        # Interactive mode
        while True:
            try:
                show_menu()
            except KeyboardInterrupt:
                console.print("\n[dim]Goodbye.[/dim]")
                break
    elif args.command == "scan":
        console.print(
            f"[bold]Scanning:[/bold] {args.target} with profile {args.profile}"
        )
        if args.dry_run:
            console.print("[green]Dry run — config valid, no scan started.[/green]")
        else:
            try:
                console.print("[cyan]Starting scan...[/cyan]")
                # TODO: Replace with real scan orchestration in Phase 1
                findings: list[dict[str, str]] = []  # placeholder until wired
                console.print(
                    f"[green]Scan complete — {len(findings)} findings.[/green]"
                )

                # --output-sarif: Write SARIF output
                if getattr(args, "output_sarif", None):
                    from pathlib import Path as _Path

                    from netra.reports.sarif import generate_sarif

                    sarif_path = generate_sarif(findings, _Path(args.output_sarif))
                    console.print(f"[green]SARIF written to {sarif_path}[/green]")

                # --fail-on: Exit with code 1 if findings meet threshold
                if getattr(args, "fail_on", None):
                    severity_order: dict[str, int] = {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                        "low": 3,
                        "info": 4,
                    }
                    threshold = severity_order[args.fail_on]
                    violating = [
                        f
                        for f in findings
                        if severity_order.get(
                            f.get("severity", "info").lower(), 4
                        )
                        <= threshold
                    ]
                    if violating:
                        console.print(
                            f"[red]FAIL: {len(violating)} finding(s) at or above "
                            f"{args.fail_on} severity.[/red]"
                        )
                        sys.exit(1)
                    else:
                        console.print(
                            f"[green]PASS: No findings at or above "
                            f"{args.fail_on} severity.[/green]"
                        )
                        sys.exit(0)
            except Exception as exc:
                console.print(f"[red]Scan error: {exc}[/red]")
                sys.exit(2)
    elif args.command == "server":
        import uvicorn
        from netra.api.app import create_app

        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        console.print(f"[yellow]{args.command} — not yet implemented[/yellow]")


if __name__ == "__main__":
    main()
