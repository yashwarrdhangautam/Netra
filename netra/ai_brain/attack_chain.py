"""
netra/ai_brain/attack_chain.py
Attack chain discovery engine.
Uses DFS graph traversal over confirmed findings to discover multi-step
exploit paths. Scores chains by combined CVSS and maps to MITRE ATT&CK.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from itertools import combinations

from netra.core.database import FindingsDB

logger = logging.getLogger("netra.ai_brain.attack_chain")

# ── MITRE ATT&CK phase order for chain sequencing ────────────────────
MITRE_PHASE_ORDER = [
    "reconnaissance",   # T1590-T1598
    "initial_access",   # T1133, T1190, T1195
    "execution",        # T1059
    "persistence",      # T1078, T1098
    "privilege_esc",    # T1068, T1134
    "lateral_move",     # T1021, T1570
    "collection",       # T1005, T1039
    "exfiltration",     # T1041, T1048
    "impact",           # T1485, T1486
]

# Technique ID → phase mapping (sample — covers common web/API techniques)
TECHNIQUE_TO_PHASE: Dict[str, str] = {
    "T1190": "initial_access",     # Exploit Public-Facing Application
    "T1133": "initial_access",     # External Remote Services
    "T1195": "initial_access",     # Supply Chain Compromise
    "T1059": "execution",          # Command and Scripting Interpreter
    "T1078": "persistence",        # Valid Accounts
    "T1098": "persistence",        # Account Manipulation
    "T1068": "privilege_esc",      # Exploitation for Privilege Escalation
    "T1134": "privilege_esc",      # Access Token Manipulation
    "T1021": "lateral_move",       # Remote Services
    "T1005": "collection",         # Data from Local System
    "T1041": "exfiltration",       # Exfiltration Over C2 Channel
    "T1485": "impact",             # Data Destruction
    "T1486": "impact",             # Data Encrypted for Impact
    "T1110": "initial_access",     # Brute Force
    "T1552": "collection",         # Unsecured Credentials
    "T1083": "collection",         # File and Directory Discovery
    "T1557": "collection",         # Adversary-in-the-Middle
}

# Category adjacency — which finding categories can chain into others
CATEGORY_GRAPH: Dict[str, List[str]] = {
    "injection":    ["auth", "data_exposure", "takeover", "rce"],
    "auth":         ["session", "takeover", "privilege_esc", "data_exposure"],
    "session":      ["takeover", "auth", "data_exposure"],
    "misconfig":    ["data_exposure", "auth", "cloud"],
    "data_exposure": ["takeover", "cloud"],
    "takeover":     ["auth", "privilege_esc"],
    "rce":          ["privilege_esc", "lateral_move", "exfiltration"],
    "cloud":        ["data_exposure", "privilege_esc", "lateral_move"],
    "api":          ["auth", "injection", "data_exposure"],
    "js_secrets":   ["auth", "api", "data_exposure"],
    "network":      ["auth", "lateral_move", "rce"],
    "xss":          ["auth", "session", "takeover"],
    "ssrf":         ["cloud", "data_exposure", "rce"],
    "xxe":          ["data_exposure", "rce", "ssrf"],
    "deserialization": ["rce", "privilege_esc"],
}

# Minimum CVSS for a finding to be a chain node
MIN_CHAIN_CVSS = 4.0

# Maximum chain depth
MAX_CHAIN_DEPTH = 6


class AttackChainDiscovery:
    """
    Discovers multi-step attack paths through confirmed findings.

    Usage:
        acd    = AttackChainDiscovery(db)
        chains = acd.discover(scan_id)
        for chain in chains:
            db.save_attack_chain(scan_id, **chain)
    """

    def __init__(self, db: FindingsDB) -> None:
        """Initialise with a FindingsDB instance."""
        self.db = db

    def discover(self, scan_id: str, min_chain_length: int = 2) -> List[dict]:
        """
        Discover all viable attack chains for a scan.

        Args:
            scan_id:          Scan to analyse.
            min_chain_length: Minimum number of nodes in a valid chain.

        Returns:
            List of chain dicts, sorted by combined CVSS descending.
        """
        from netra.core.utils import status

        # Only chain confirmed findings with adequate CVSS
        all_findings = self.db.get_findings(scan_id=scan_id, exclude_fps=True)
        candidates   = [
            f for f in all_findings
            if (f.get("cvss_score") or 0) >= MIN_CHAIN_CVSS
            and f.get("status") != "fp"
        ]

        if len(candidates) < 2:
            status("Not enough candidates for chain discovery", "info")
            return []

        status(f"Building attack graph with {len(candidates)} finding nodes", "ai")

        # Build adjacency list: finding_id → list of finding_ids reachable from it
        adj = self._build_adjacency(candidates)

        # DFS to discover all chains
        chains: List[dict] = []
        visited_chains: Set[tuple] = set()

        for start in candidates:
            if start.get("severity") in ("critical", "high"):
                paths = self._dfs(start, adj, candidates, max_depth=MAX_CHAIN_DEPTH)
                for path in paths:
                    if len(path) >= min_chain_length:
                        chain_key = tuple(sorted(p["id"] for p in path))
                        if chain_key not in visited_chains:
                            visited_chains.add(chain_key)
                            chain = self._build_chain(path)
                            if chain:
                                chains.append(chain)

        # Sort by combined CVSS descending
        chains.sort(key=lambda c: c["combined_cvss"], reverse=True)

        # Cap at top 20 chains to avoid DB bloat
        chains = chains[:20]
        status(f"Discovered {len(chains)} attack chains", "ok")

        return chains

    def _build_adjacency(self, findings: List[dict]) -> Dict[int, List[int]]:
        """
        Build an adjacency list based on category-to-category connections
        and host proximity.

        Args:
            findings: List of candidate findings.

        Returns:
            Dict mapping finding_id → list of reachable finding_ids.
        """
        adj: Dict[int, List[int]] = {f["id"]: [] for f in findings}

        for f1, f2 in combinations(findings, 2):
            if f1["id"] == f2["id"]:
                continue
            if self._can_chain(f1, f2):
                adj[f1["id"]].append(f2["id"])
            if self._can_chain(f2, f1):
                adj[f2["id"]].append(f1["id"])

        return adj

    def _can_chain(self, f_from: dict, f_to: dict) -> bool:
        """
        Determine if f_from can chain into f_to.

        Chaining criteria:
          - Category graph edge exists (from → to category)
          - OR same host (same host often means one vuln enables another)
          - f_to must have higher or equal severity, OR be a different category

        Args:
            f_from: Source finding.
            f_to:   Target finding.

        Returns:
            True if a chain edge should exist.
        """
        from_cat  = (f_from.get("category") or "").lower()
        to_cat    = (f_to.get("category") or "").lower()
        same_host = f_from.get("host") == f_to.get("host") and f_from.get("host")

        # Category graph edge
        reachable = CATEGORY_GRAPH.get(from_cat, [])
        cat_edge  = to_cat in reachable

        # Same host — different categories always potentially chainable
        host_edge = same_host and from_cat != to_cat

        return cat_edge or host_edge

    def _dfs(
        self,
        current: dict,
        adj: Dict[int, List[int]],
        id_map: List[dict],
        path: List[dict] = None,
        visited: Set[int] = None,
        max_depth: int = MAX_CHAIN_DEPTH,
    ) -> List[List[dict]]:
        """
        Depth-first search for all paths from current finding.

        Args:
            current:   Current node (finding dict).
            adj:       Adjacency list.
            id_map:    All candidate findings (to look up by ID).
            path:      Current path being built.
            visited:   Set of visited finding IDs.
            max_depth: Maximum chain depth.

        Returns:
            List of paths, where each path is a list of finding dicts.
        """
        if path is None:
            path = []
        if visited is None:
            visited = set()

        path    = path + [current]
        visited = visited | {current["id"]}

        if len(path) >= max_depth:
            return [path] if len(path) >= 2 else []

        paths   = [path] if len(path) >= 2 else []
        id_lookup = {f["id"]: f for f in id_map}

        for neighbour_id in adj.get(current["id"], []):
            if neighbour_id not in visited:
                neighbour = id_lookup.get(neighbour_id)
                if neighbour:
                    sub_paths = self._dfs(
                        neighbour, adj, id_map, path, visited, max_depth
                    )
                    paths.extend(sub_paths)

        return paths

    def _build_chain(self, path: List[dict]) -> Optional[dict]:
        """
        Build a chain dict from a DFS path.

        Args:
            path: Ordered list of finding dicts forming the chain.

        Returns:
            Chain dict with combined CVSS, MITRE sequence, and node IDs.
        """
        if len(path) < 2:
            return None

        node_ids     = [f["id"] for f in path]
        cvss_scores  = [f.get("cvss_score") or 0 for f in path]
        combined     = self._compute_combined_cvss(cvss_scores)
        mitre_seq    = self._build_mitre_sequence(path)

        return {
            "nodes":          node_ids,
            "combined_cvss":  combined,
            "mitre_sequence": mitre_seq,
            "path_summary":   " → ".join(
                f"{f.get('category','?')}@{f.get('host','?')}" for f in path
            ),
        }

    def _compute_combined_cvss(self, scores: List[float]) -> float:
        """
        Compute a combined CVSS for a chain.
        Uses a diminishing returns formula: each subsequent finding adds
        less to the total, capped at 10.0.

        Args:
            scores: List of individual CVSS scores.

        Returns:
            Combined score 0.0–10.0.
        """
        if not scores:
            return 0.0

        scores  = sorted(scores, reverse=True)
        base    = scores[0]
        bonus   = sum(s * (0.5 ** (i + 1)) for i, s in enumerate(scores[1:]))
        combined = min(base + bonus, 10.0)
        return round(combined, 1)

    def _build_mitre_sequence(self, path: List[dict]) -> str:
        """
        Map chain findings to MITRE ATT&CK techniques and order by attack phase.

        Args:
            path: Ordered list of finding dicts.

        Returns:
            String like "T1190 → T1059 → T1078".
        """
        techniques: List[Tuple[str, str]] = []  # (phase, technique_id)

        for f in path:
            t = (f.get("mitre_technique") or "").strip()
            if t and t.startswith("T"):
                tid   = t.split(",")[0].strip()
                phase = TECHNIQUE_TO_PHASE.get(tid, "unknown")
                techniques.append((phase, tid))

        if not techniques:
            return "Unknown Sequence"

        # Sort by phase order
        def phase_key(item: Tuple[str, str]) -> int:
            """Return sort key for MITRE phase ordering."""
            ph = item[0]
            try:
                return MITRE_PHASE_ORDER.index(ph)
            except ValueError:
                return 999

        techniques.sort(key=phase_key)
        return " → ".join(t[1] for t in techniques)


def discover_and_save_chains(scan_id: str, db: FindingsDB) -> int:
    """
    Convenience function: discover attack chains and persist them to the DB.

    Args:
        scan_id: Scan to analyse.
        db:      FindingsDB instance.

    Returns:
        Number of chains discovered and saved.
    """
    engine = AttackChainDiscovery(db)
    chains = engine.discover(scan_id)

    for chain in chains:
        db.save_attack_chain(
            scan_id        = scan_id,
            nodes          = chain["nodes"],
            combined_cvss  = chain["combined_cvss"],
            mitre_sequence = chain["mitre_sequence"],
            narrative      = "",   # narrative filled in by narrative.py
        )

    return len(chains)
