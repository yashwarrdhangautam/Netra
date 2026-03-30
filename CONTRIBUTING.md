# Contributing to NETRA

Thank you for your interest in contributing to NETRA! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Welcome newcomers and help them learn

## Getting Started

### Prerequisites
- Python 3.12+
- Poetry for dependency management
- Docker and Docker Compose (for containerized development)
- Git

### Setting Up Development Environment

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/netra.git
   cd netra
   ```

2. **Install dependencies:**
   ```bash
   poetry install
   ```

3. **Set up pre-commit hooks:**
   ```bash
   make pre-commit-install
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

## Development Workflow

### Making Changes

1. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below.

3. **Run tests:**
   ```bash
   make test
   ```

4. **Run linting and type checking:**
   ```bash
   make lint
   make typecheck
   ```

5. **Commit your changes:**
   ```bash
   git commit -m "feat: add your feature description"
   ```

### Coding Standards

- **Type hints:** All functions must have type hints for parameters and return values
- **Documentation:** Add docstrings to public functions and classes
- **Testing:** Write tests for new functionality
- **Formatting:** Code is automatically formatted with ruff
- **Security:** Follow OWASP Top 10 secure coding practices

### Commit Message Convention

We use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or modifications
- `chore:` Maintenance tasks

Example:
```
feat: add SQL injection testing with sqlmap

- Implement sqlmap tool wrapper
- Add configuration for risk levels
- Include safe mode for detection-only scans
```

## Submitting Changes

1. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub with:
   - Clear title following conventional commits
   - Description of changes
   - Reference to any related issues
   - Screenshots if UI changes

3. **Address review feedback** promptly

## Testing

### Running Tests
```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/test_api/test_scans.py
```

### Writing Tests
- Place tests in the `tests/` directory
- Mirror the source structure
- Use fixtures from `conftest.py`
- Mark async tests with `@pytest.mark.asyncio`

## Questions?

- Check existing issues and discussions
- Read the documentation in `docs/`
- Ask in GitHub Discussions

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.
