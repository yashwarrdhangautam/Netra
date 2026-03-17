# Contributing to NETRA नेत्र

Thank you for your interest in contributing! NETRA is built by the security community, for the security community.

## Code of Conduct

Be respectful, constructive, and inclusive. We are here to build great security tools together.

## Getting Started

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/netra.git
cd netra

# 2. Create a feature branch
git checkout -b feature/your-feature-name

# 3. Set up development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install ruff black pytest pytest-asyncio

# 4. Install Ollama and pull Qwen (for AI tests)
ollama pull qwen:14b
```

## Branch Naming

| Prefix | Use for |
|--------|---------|
| `feature/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation only |
| `test/` | Tests only |
| `refactor/` | Code refactoring |

## Code Standards

**Type hints** — Every function must have type annotations:
```python
def my_func(host: str, port: int = 80) -> dict:
```

**Docstrings** — Every function and class needs a docstring:
```python
def my_func(host: str) -> dict:
    """Run a probe against host and return findings dict."""
```

**Formatting** — Run before committing:
```bash
black netra/ netra.py
ruff check netra/ netra.py --fix
```

**No credentials** — Never hardcode API keys, passwords, or tokens.

**No `sentinal` references** — The old codebase used this name. NETRA only.

## Adding a New Scan Module

1. Create `netra/modules/vapt/your_module.py`
2. Follow the pattern of existing modules (e.g. `injection.py`)
3. Use `netra.core.utils.run_cmd()` for all external tool calls
4. Use `netra.core.database.FindingsDB` for all DB writes
5. Add type hints + docstrings
6. Register in `netra/modules/vapt/__init__.py`

## Adding a Compliance Standard

1. Open `netra/ai_brain/config_audit.py`
2. Add a new `YOUR_STANDARD_CHECKS` dict following the pattern
3. Add to `STANDARDS_MAP`
4. Update `config.yaml` and `README.md`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_analyzer.py -v

# Check syntax across all files
python3 -c "
import ast
from pathlib import Path
for f in Path('netra').rglob('*.py'):
    ast.parse(f.read_text())
print('All files clean')
"
```

## Submitting a Pull Request

1. Make sure tests pass and code is formatted
2. Update `CHANGELOG.md` under `[Unreleased]`
3. Push to your fork and open a PR against `main`
4. Fill in the PR template
5. Link any related issues

## Reporting Issues

Use GitHub Issues with the bug report or feature request template. Include:
- Your OS and Python version
- `python3 netra.py --version` output
- Full error output (redact any sensitive data)

## Contact

- GitHub Issues (preferred)
- Email: yash@netra.security

