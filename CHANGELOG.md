# Changelog

All notable changes to NETRA are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-05-11

### Added
- NETRA-BB program registry, scope sync, and scope validation workflow
- Agentic hunt planning, routing, execution, and explain surfaces
- GUI support for bug bounty programs, hunts, PoC Lab, submissions, graph context, and audit views
- Graphify-backed repository memory for lower-token planning context
- Learning corpus ingestion for HackerOne hacktivity, GHSA / NVD advisories, and RSS/writeup feeds
- Learning trends CLI/API and GUI surfaces
- Corpus controls for source toggles, freshness checks, forget, and re-embed workflows
- Safe verifier allowlist and replay controls for read-only PoC verification
- PostgreSQL `pgvector` acceleration path with local fallback

### Changed
- Updated submission drafting so comparable public reports stay as internal operator context instead of being rendered into final submission markdown
- Added embedding model version tracking to corpus rows to avoid mixed-vector retrieval
- Improved cancellation and agentic orchestration plumbing across the bug bounty workflow
- Refreshed release documentation for the v1 line

### Security
- Added robots.txt enforcement, per-host rate limiting, and `Retry-After` handling for learning sources
- Added anti-leak draft overlap guard for public prior-art retrieval
- Preserved server-side scope enforcement and verifier allowlist gating throughout the bug bounty flow

## [0.1.0]

Initial internal development line before the v1 release track.
