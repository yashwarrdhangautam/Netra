# NETRA v1.0.0

## Highlights

- First end-to-end NETRA-BB release line
- Local-first bug bounty workflow with program registry, scope enforcement, hunts, PoC Lab, submissions, and verdict tracking
- Agentic planner/router/executor with Graphify-backed repo memory
- Learning corpus ingestion for public prior art with safe local retrieval
- PostgreSQL `pgvector` acceleration path with local fallback

## Included in this release

### Bug bounty operations
- Program registration and scope sync
- Scope checker and scope-block audit trail
- Passive and agentic hunt flows
- Replay-backed verification with allowlisted verifiers
- Submission drafting and verdict ingestion

### AI and reasoning
- Multi-agent coordination layer
- BountyHunter scoring with comparable prior-art context
- Graph-backed attack-path hints
- Hunt explain and plan preview surfaces

### Learning subsystem
- HackerOne hacktivity ingestion
- GHSA / NVD ingestion
- RSS/writeup ingestion
- Trends, corpus forget, corpus re-embed
- Anti-leak protections for draft generation

### GUI
- BB console
- Programs
- Scope Center
- Hunts
- PoC Lab
- Submissions
- Graph and audit surfaces

## Upgrade notes

- Run `alembic upgrade head`
- Rebuild Docker images if you deploy with Docker
- If you change the embedding model, run:

```bash
poetry run netra-bb corpus reembed --confirm REEMBED
```

## Known limitations

- Windows async test teardown behavior still needs cleanup in some environments
- `pgvector` acceleration is active on PostgreSQL; SQLite stays on the local fallback path by design
