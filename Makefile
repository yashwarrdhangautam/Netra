# NETRA Development Makefile

.PHONY: help install dev test lint typecheck clean docker-build docker-up docker-down migrate seed

help: ## Show this help message
	@echo "NETRA Development Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

install: ## Install dependencies with Poetry
	poetry install

dev: ## Install dev dependencies with Poetry
	poetry install --with dev

test: ## Run tests with coverage
	poetry run pytest

test-cov: ## Run tests with HTML coverage report
	poetry run pytest --cov=netra --cov-report=html
	@echo "Coverage report: open htmlcov/index.html"

lint: ## Run linter (ruff)
	poetry run ruff check src/ tests/

lint-fix: ## Run linter and fix issues
	poetry run ruff check src/ tests/ --fix

format: ## Format code with ruff
	poetry run ruff format src/ tests/

typecheck: ## Run type checker (mypy)
	poetry run mypy src/

clean: ## Clean build artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf dist/ build/

docker-build: ## Build Docker images
	docker compose build

docker-up: ## Start Docker containers
	docker compose up -d

docker-down: ## Stop Docker containers
	docker compose down

docker-logs: ## Show Docker logs
	docker compose logs -f

migrate: ## Run database migrations
	poetry run alembic upgrade head

migrate-revision: ## Create new migration (usage: make migrate-revision message="description")
	poetry run alembic revision --autogenerate -m "$(message)"

migrate-downgrade: ## Downgrade one migration
	poetry run alembic downgrade -1

seed: ## Seed database with initial data
	poetry run python scripts/seed_db.py --all

server: ## Start FastAPI server
	poetry run uvicorn netra.api.app:create_app --factory --reload --host 0.0.0.0 --port 8000

cli: ## Run NETRA CLI
	poetry run netra

mcp: ## Run MCP server
	poetry run python -m netra.mcp.server

pre-commit: ## Run pre-commit hooks
	pre-commit run --all-files

pre-commit-install: ## Install pre-commit hooks
	pre-commit install

ci: ## Run all CI checks
	make lint
	make typecheck
	make test
