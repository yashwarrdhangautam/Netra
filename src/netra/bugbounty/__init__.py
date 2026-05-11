"""NETRA-BB — Bug bounty hunting module.

This module turns NETRA into a scope-aware AI bug bounty agent. It plugs into the
existing scanner orchestrator, AI consensus brain, MCP server, and report engine,
adding programs / scope rules / submissions / dedup as new domain concepts.

Module layout (see docs/NETRA_BB_Architecture.docx for the full design):
    programs.py       — Program registry CRUD + scope diff detection
    scope.py          — Pure-Python scope validator (the safety gate; NO AI)
    recon/            — Passive + scope-gated active recon
    triage/           — BountyHunter persona, deduper, severity mapping
    submission/       — Draft generation, payout estimator, state machine
    graph_indexer.py  — Graphify ingestion + queries
    cli.py            — `netra bb …` CLI subcommands

The scope validator is the single most important piece. It is pure Python with zero
AI in the path. AI may RECOMMEND scope changes; only an operator can ACCEPT them.
"""
from netra.bugbounty.scope import (
    ScopeDecision,
    ScopeValidator,
    ScopeViolation,
    parse_target,
)

__all__ = [
    "ScopeDecision",
    "ScopeValidator",
    "ScopeViolation",
    "parse_target",
]
