# Contributing to NETRA

Thanks for helping improve NETRA.

This project mixes backend orchestration, frontend operator workflows, and security-focused product design, so good contributions tend to be small, explicit, and test-backed.

## Before you start

- Read the current [README.md](README.md)
- Check the relevant docs in [docs/](docs/)
- Prefer opening an issue or a focused draft PR before large changes

## Development setup

### Prerequisites
- Python 3.12+
- Poetry
- Node.js 22+
- Docker and Docker Compose

### Install

```bash
git clone https://github.com/yashwarrdhangautam/Netra.git
cd Netra
poetry install
cd frontend && npm install
```

### Environment

```bash
cp .env.example .env
```

Set local values for the services you want to use. For bug bounty work, Ollama and platform credentials are the main ones.

## Local checks

### Backend

```bash
$env:PYTHONPATH="src"
pytest
alembic upgrade head
```

### Frontend

```bash
cd frontend
npm.cmd run build
```

### Docker

```bash
docker compose up --build
```

## Contribution rules

### Code
- Add type hints
- Follow the existing local patterns before introducing new abstractions
- Keep edits scoped to the feature or bug being addressed
- Do not silently weaken scope or safety checks

### Tests
- Add or update tests for behavior changes
- Prefer focused regression tests when fixing bugs
- For bug bounty features, include safety-path assertions where relevant

### Security and safety
- Scope enforcement must remain server-side
- Verifier behavior must stay allowlist-driven
- Public prior art may inform reasoning, but should not be copied into operator-facing outputs without explicit safeguards

## Commit style

Use conventional-style commit messages where practical:

- `feat:`
- `fix:`
- `docs:`
- `test:`
- `refactor:`
- `chore:`

Examples:

```text
feat: add corpus source rate limiting
fix: block verbatim overlap in submission drafts
docs: refresh README for v1.0.0 release
```

## Pull requests

Please include:
- a clear summary
- what changed
- how it was tested
- screenshots for GUI changes when useful

If a change touches bug bounty safety controls, call that out explicitly in the PR description.

## Release hygiene

For release-facing changes, update the relevant docs:
- [README.md](README.md)
- [CHANGELOG.md](CHANGELOG.md)
- [docs/bugbounty.md](docs/bugbounty.md)
- any API or configuration docs affected by the change

## Questions

If something is ambiguous, open the smallest question that unblocks the work. Small, explicit communication beats a broad guess here.
