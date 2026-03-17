"""
netra/core/checkpoint.py
Phase-aware checkpoint + resume system.
Saves after every phase. Detects incomplete runs on startup.
should_run() is the key function — called before EVERY phase.
"""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

PHASES = [
    "0_input",
    "1_osint",
    "2_subdomains",
    "3_discovery",
    "4_ports",
    "5_vulns",
    "6_pentest",
    "7_auth_session",
    "8_ai_surface",
    "9_enrichment",
    "10_ai_analysis",
    "11_reports",
    "complete",
]

PHASE_IDX = {p: i for i, p in enumerate(PHASES)}


class Checkpoint:
    """
    Manages scan state for a single workdir.

    Usage:
        cp = Checkpoint(workdir)
        if cp.should_run("2_subdomains"):
            ... run subdomains ...
            cp.done("2_subdomains")
    """

    def __init__(self, workdir: Path) -> None:
        """Initialise and load existing checkpoint if present."""
        self.workdir    = Path(workdir)
        self.path       = self.workdir / "checkpoint.json"
        self.data: dict = {}
        self._load()

    def _load(self) -> None:
        """Load checkpoint data from disk."""
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except Exception:
                self.data = {}

    def _save(self) -> None:
        """Persist checkpoint data to disk."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2))

    def init(self, targets_meta: dict) -> None:
        """Initialise a new scan checkpoint with target metadata."""
        self.data = {
            "workdir":           str(self.workdir),
            "started_at":        datetime.utcnow().isoformat(),
            "updated_at":        datetime.utcnow().isoformat(),
            "phase":             "0_input",
            "completed_phases":  [],
            "targets":           targets_meta,
            "scan_id":           f"scan_{int(time.time())}",
        }
        self._save()

    def done(self, phase: str, meta: dict = None) -> None:
        """Mark a phase as complete. Call after phase finishes."""
        if phase not in self.data.get("completed_phases", []):
            self.data.setdefault("completed_phases", []).append(phase)
        self.data["phase"]      = phase
        self.data["updated_at"] = datetime.utcnow().isoformat()
        if meta:
            self.data.setdefault("phase_meta", {})[phase] = meta
        self._save()

    def should_run(self, phase: str, resume_from: str = None) -> bool:
        """
        Return True if this phase should run.
        If resume_from is set, skip phases that already completed.

        Args:
            phase:       Phase name to check.
            resume_from: If set, skip phases already done or before this point.

        Returns:
            True if the phase should execute, False to skip.
        """
        completed = self.data.get("completed_phases", [])

        if resume_from is None:
            return True

        if phase in completed:
            print(f"  [skip] {phase} — already completed")
            return False

        resume_idx = PHASE_IDX.get(resume_from, 0)
        phase_idx  = PHASE_IDX.get(phase, 999)
        if phase_idx < resume_idx:
            print(f"  [skip] {phase} — before resume point {resume_from}")
            return False

        return True

    def is_complete(self) -> bool:
        """Return True if the scan ran to completion."""
        return "complete" in self.data.get("completed_phases", [])

    def get_last_phase(self) -> str:
        """Return the last phase that was started."""
        return self.data.get("phase", "0_input")

    def get_scan_id(self) -> str:
        """Return the unique scan ID for this checkpoint."""
        return self.data.get("scan_id", "unknown")

    def clear(self) -> None:
        """Delete the checkpoint file and reset data."""
        if self.path.exists():
            self.path.unlink()
        self.data = {}

    def summary(self) -> str:
        """Return a human-readable summary for display."""
        completed = self.data.get("completed_phases", [])
        last      = self.data.get("phase", "none")
        started   = self.data.get("started_at", "?")
        return (
            f"  Scan ID:   {self.data.get('scan_id', '?')}\n"
            f"  Started:   {started[:19].replace('T', ' ')}\n"
            f"  Last phase:{last}\n"
            f"  Completed: {len(completed)} phases"
        )


def find_resumable_scans(output_dir: str) -> list:
    """
    Scan output_dir for incomplete checkpoint files.

    Returns:
        List of (workdir_path, checkpoint_data) tuples.
    """
    output_path = Path(output_dir)
    resumable: list = []

    if not output_path.exists():
        return resumable

    for cp_file in sorted(output_path.rglob("checkpoint.json")):
        try:
            data = json.loads(cp_file.read_text())
            completed = data.get("completed_phases", [])
            if "complete" not in completed and len(completed) > 0:
                resumable.append((cp_file.parent, data))
        except Exception:
            continue

    return resumable


def check_resume_prompt(output_dir: str) -> Optional[tuple]:
    """
    On startup: scan for incomplete runs and prompt user to resume.

    Returns:
        (workdir, resume_from_phase) tuple, or None if starting fresh.
    """
    resumable = find_resumable_scans(output_dir)
    if not resumable:
        return None

    print("\n" + "═" * 60)
    print("  INCOMPLETE SCANS DETECTED")
    print("═" * 60)

    for i, (workdir, data) in enumerate(resumable[:5]):
        completed = data.get("completed_phases", [])
        last      = data.get("phase", "?")
        started   = data.get("started_at", "?")[:19].replace("T", " ")
        scan_id   = data.get("scan_id", "?")
        print(f"\n  [{i + 1}] {workdir.name}")
        print(f"       ID:      {scan_id}")
        print(f"       Started: {started}")
        print(f"       Stopped: after {last}")
        print(f"       Done:    {len(completed)} phases")

    print(f"\n  [0] Start a new scan")
    print()

    while True:
        choice = input("  Resume which scan? (0 to start new): ").strip()
        if choice == "0":
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(resumable):
                workdir, data = resumable[idx]
                last_phase    = data.get("phase", PHASES[0])
                print(f"\n  ✓ Resuming from: {last_phase}")
                return (workdir, last_phase)
        except ValueError:
            pass
        print("  Invalid choice. Try again.")
