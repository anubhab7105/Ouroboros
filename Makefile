# =============================================================================
# MULEGUARD Makefile
# -----------------------------------------------------------------------------
# Advanced command surface for:
# - local installation
# - database migrations
# - synthetic data seeding/reset
# - ML training/evaluation
# - backend/frontend development
# - linting/typechecking/testing/building
# - Docker Compose operations
# - smoke checks
# - project tree generation
# - cleanup
#
# Note:
# This Makefile uses GNU Make's .RECIPE_PREFIX feature to avoid tab-copy issues.
# If your Make implementation requires tabs, remove .RECIPE_PREFIX and indent
# all recipe lines with real tabs.
# =============================================================================

.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.RECIPE_PREFIX = >

# Pull local environment variables if present.
# This allows values such as BACKEND_PORT, POSTGRES_USER, and DEV_ANALYST_PASSWORD
# to be reused by Make targets. Do not commit secrets.
-include .env

# -----------------------------------------------------------------------------
# Configurable variables
# -----------------------------------------------------------------------------

ROOT_DIR ?= .
BACKEND_DIR ?= backend
FRONTEND_DIR ?= frontend
VENV ?= .venv

ifeq ($(OS),Windows_NT)
    VENV_BIN ?= $(VENV)/Scripts
    SYS_PYTHON ?= python
    VENV_PYTHON ?= $(VENV_BIN)/python.exe
else
    VENV_BIN ?= $(VENV)/bin
    SYS_PYTHON ?= python3
    VENV_PYTHON ?= $(VENV_BIN)/python
endif

PIP ?= $(VENV_PYTHON) -m pip
ALEMBIC ?= $(VENV_PYTHON) -m alembic
PYTEST ?= $(VENV_PYTHON) -m pytest
RUFF ?= $(VENV_PYTHON) -m ruff
MYPY ?= $(VENV_PYTHON) -m mypy
UVICORN ?= $(VENV_PYTHON) -m uvicorn

NPM ?= npm
COMPOSE ?= docker compose

BACKEND_APP ?= app.main:app
BACKEND_HOST ?= 0.0.0.0
BACKEND_PORT ?= 8000
FRONTEND_PORT ?= 8080
API_BASE ?= http://localhost:$(BACKEND_PORT)/api/v1

POSTGRES_USER ?= muleguard
POSTGRES_DB ?= muleguard

SEED ?= 42
MSG ?= schema update
CONFIRM ?= 0

PYTEST_ARGS ?= -q
ANALYZE_USERNAME ?= analyst
ANALYZE_PASSWORD ?= $(DEV_ANALYST_PASSWORD)

# -----------------------------------------------------------------------------
# Phony targets
# -----------------------------------------------------------------------------

.PHONY: help \
        env \
        check-tools \
        doctor \
        require-env \
        require-venv \
        require-python \
        require-npm \
        require-curl \
        require-docker \
        install \
        install-backend \
        install-frontend \
        bootstrap \
        migrate \
        revision \
        seed \
        seed-reset \
        seed-large \
        generate-data \
        import-sample-data \
        check-schemas \
        dev-backend \
        dev-frontend \
        analyze \
        train-model \
        evaluate-model \
        test \
        test-backend \
        test-frontend \
        test-e2e \
        coverage \
        coverage-html \
        lint \
        lint-backend \
        lint-frontend \
        typecheck \
        typecheck-backend \
        typecheck-frontend \
        format \
        format-backend \
        format-frontend \
        build \
        build-frontend \
        ci \
        verify \
        precommit \
        docker-build \
        docker-up \
        docker-down \
        docker-restart \
        docker-logs \
        docker-logs-backend \
        docker-logs-frontend \
        docker-ps \
        docker-reset \
        docker-reset-full \
        fresh-demo \
        reset-demo \
        db-shell \
        backend-shell \
        health \
        ready \
        openapi \
        api-docs \
        frontend-url \
        smoke \
        tree \
        clean \
        clean-python \
        clean-frontend-cache \
        clean-venv \
        clean-node \
        clean-all \
        generate-secret \
        generate-password \
        env-warn \
        check-secrets \
        security-check \
        freeze \
        outdated \
        audit-frontend

# -----------------------------------------------------------------------------
# Help / diagnostics
# -----------------------------------------------------------------------------

help: ## Show available Make targets
> @awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check-tools: ## Check required command-line tools
> @echo "Checking tools..."
> @command -v $(SYS_PYTHON) >/dev/null 2>&1 || echo "WARNING: $(SYS_PYTHON) not found"
> @command -v $(NPM) >/dev/null 2>&1 || echo "WARNING: $(NPM) not found"
> @command -v docker >/dev/null 2>&1 || echo "WARNING: docker not found"
> @command -v curl >/dev/null 2>&1 || echo "WARNING: curl not found"
> @echo "Tool check complete."

doctor: check-tools ## Diagnose local environment
> @echo "Python: $$($(SYS_PYTHON) --version 2>&1 || echo missing)"
> @echo "Node: $$(node --version 2>&1 || echo missing)"
> @echo "npm: $$($(NPM) --version 2>&1 || echo missing)"
> @echo "Docker: $$(docker --version 2>&1 || echo missing)"
> @echo "Docker Compose: $$(docker compose version 2>&1 || echo missing)"
> @test -f .env && echo ".env: present" || echo ".env: missing (run: make env)"
> @test -x $(VENV_PYTHON) && echo "venv: present" || echo "venv: missing (run: make install-backend)"

env: ## Create .env from .env.example if missing
> @if [ ! -f .env ]; then \
>   cp .env.example .env; \
>   echo "Created .env from .env.example"; \
> else \
>   echo ".env already exists"; \
> fi

env-warn: require-env ## Show remaining CHANGE_ME placeholders in .env
> @grep -n "CHANGE_ME" .env || echo "No CHANGE_ME placeholders found."

# -----------------------------------------------------------------------------
# Internal guards
# -----------------------------------------------------------------------------

require-env:
> @if [ ! -f .env ]; then \
>   echo "ERROR: .env not found."; \
>   echo "Run: make env"; \
>   exit 1; \
> fi

require-venv:
> @if [ ! -x $(VENV_PYTHON) ]; then \
>   echo "ERROR: Python virtual environment not found."; \
>   echo "Run: make install-backend"; \
>   exit 1; \
> fi

require-python:
> @command -v $(SYS_PYTHON) >/dev/null 2>&1 || { \
>   echo "ERROR: Python not found. Install Python 3.11+ or set SYS_PYTHON."; \
>   exit 1; \
> }

require-npm:
> @command -v $(NPM) >/dev/null 2>&1 || { \
>   echo "ERROR: npm not found. Install Node.js 20+."; \
>   exit 1; \
> }

require-curl:
> @command -v curl >/dev/null 2>&1 || { \
>   echo "ERROR: curl is required for this target."; \
>   exit 1; \
> }

require-docker:
> @command -v docker >/dev/null 2>&1 || { \
>   echo "ERROR: docker not found."; \
>   exit 1; \
> }
> @docker compose version >/dev/null 2>&1 || { \
>   echo "ERROR: Docker Compose v2 not found."; \
>   exit 1; \
> }

# -----------------------------------------------------------------------------
# Installation and bootstrap
# -----------------------------------------------------------------------------

install: install-backend install-frontend ## Install backend and frontend dependencies

install-backend: require-python ## Create virtualenv and install backend dependencies
> @$(SYS_PYTHON) -m venv $(VENV)
> @$(PIP) install --upgrade pip
> @$(PIP) install -r $(BACKEND_DIR)/requirements-dev.txt

install-frontend: require-npm ## Install frontend dependencies
> @cd $(FRONTEND_DIR) && if [ -f package-lock.json ]; then \
>   $(NPM) ci; \
> else \
>   $(NPM) install; \
> fi

bootstrap: install migrate seed ## Install dependencies, migrate database, seed synthetic data

# -----------------------------------------------------------------------------
# Database migrations
# -----------------------------------------------------------------------------

migrate: require-env require-venv ## Apply Alembic migrations
> cd $(BACKEND_DIR) && $(ALEMBIC) upgrade head

revision: require-env require-venv ## Create Alembic revision: make revision MSG="description"
> cd $(BACKEND_DIR) && $(ALEMBIC) revision --autogenerate -m "$(MSG)"

# -----------------------------------------------------------------------------
# Synthetic data
# -----------------------------------------------------------------------------

seed: require-env require-venv migrate ## Seed deterministic synthetic demo data
> cd $(BACKEND_DIR) && $(VENV_PYTHON) -m app.ingestion.seed

seed-reset: require-env require-venv ## Destructive reset/reseed synthetic demo DB
> @if [ "$(CONFIRM)" != "1" ]; then \
>   echo "This is destructive."; \
>   echo "Run: make seed-reset CONFIRM=1"; \
>   exit 1; \
> fi
> cd $(BACKEND_DIR) && $(VENV_PYTHON) -m app.ingestion.seed --reset --confirm-local-demo

seed-large: require-env require-venv migrate ## Seed larger synthetic dataset
> cd $(BACKEND_DIR) && SEED_LARGE_DATASET=true $(VENV_PYTHON) -m app.ingestion.seed

generate-data: require-venv ## Generate synthetic JSON files into data/generated
> PYTHONPATH=$(BACKEND_DIR) $(VENV_PYTHON) scripts/generate_data.py

import-sample-data: require-env require-venv ## Import sample JSON data
> PYTHONPATH=$(BACKEND_DIR) $(VENV_PYTHON) scripts/import_json.py

check-schemas: require-venv ## Validate JSON schemas and sample payloads
> PYTHONPATH=$(BACKEND_DIR) $(VENV_PYTHON) scripts/check_schemas.py

# -----------------------------------------------------------------------------
# Local development servers
# -----------------------------------------------------------------------------

dev-backend: require-env require-venv ## Start FastAPI backend with reload
> cd $(BACKEND_DIR) && $(UVICORN) $(BACKEND_APP) --reload --host $(BACKEND_HOST) --port $(BACKEND_PORT)

dev-frontend: ## Start Vite frontend development server
> cd $(FRONTEND_DIR) && $(NPM) run dev

# -----------------------------------------------------------------------------
# Analysis / ML
# -----------------------------------------------------------------------------

analyze: require-env require-venv require-curl ## Run analysis against local API
> @if [ -z "$(ANALYZE_PASSWORD)" ]; then \
>   echo "ERROR: ANALYZE_PASSWORD is not set."; \
>   echo "Set ANALYZE_PASSWORD or DEV_ANALYST_PASSWORD in .env."; \
>   exit 1; \
> fi
> @TOKEN=$$(curl -fsS -X POST $(API_BASE)/auth/login \
>   -H 'Content-Type: application/json' \
>   -d "{\"username\":\"$(ANALYZE_USERNAME)\",\"password\":\"$(ANALYZE_PASSWORD)\"}" \
>   | $(VENV_PYTHON) -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))'); \
> if [ -z "$$TOKEN" ]; then \
>   echo "ERROR: API login failed."; \
>   exit 1; \
> fi; \
> curl -fsS -X POST $(API_BASE)/analysis/run \
>   -H "Authorization: Bearer $$TOKEN" \
>   -H 'Content-Type: application/json' \
>   | $(VENV_PYTHON) -m json.tool

train-model: require-env require-venv ## Train supervised/anomaly models
> cd $(BACKEND_DIR) && $(VENV_PYTHON) -m app.ml.train_model --seed $(SEED)

evaluate-model: require-env require-venv ## Evaluate trained model artifacts
> PYTHONPATH=$(BACKEND_DIR) $(VENV_PYTHON) scripts/evaluate_model.py

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

test: test-backend test-frontend ## Run backend tests and frontend checks

test-backend: require-env require-venv ## Run backend Pytest suite
> cd $(BACKEND_DIR) && $(PYTEST) $(PYTEST_ARGS)

test-frontend: require-npm ## Run frontend tests/typecheck/build
> cd $(FRONTEND_DIR) && $(NPM) run test --if-present
> cd $(FRONTEND_DIR) && $(NPM) run typecheck
> cd $(FRONTEND_DIR) && $(NPM) run build

test-e2e: require-env require-venv ## Run end-to-end workflow test
> cd $(BACKEND_DIR) && $(PYTEST) -q tests/test_e2e_workflow.py

coverage: require-venv ## Run backend coverage report in terminal
> cd $(BACKEND_DIR) && $(VENV_PYTHON) -m pytest --cov=app --cov-report=term-missing

coverage-html: require-venv ## Generate backend HTML coverage report
> cd $(BACKEND_DIR) && $(VENV_PYTHON) -m pytest --cov=app --cov-report=html

# -----------------------------------------------------------------------------
# Lint / typecheck / format / build
# -----------------------------------------------------------------------------

lint: lint-backend lint-frontend ## Lint backend and frontend

lint-backend: require-venv ## Lint backend with Ruff
> cd $(BACKEND_DIR) && $(RUFF) check app tests
> cd $(BACKEND_DIR) && $(RUFF) format --check app tests

lint-frontend: require-npm ## Lint frontend
> cd $(FRONTEND_DIR) && $(NPM) run lint

typecheck: typecheck-backend typecheck-frontend ## Typecheck backend and frontend

typecheck-backend: require-venv ## Typecheck backend with mypy
> cd $(BACKEND_DIR) && $(MYPY) app

typecheck-frontend: require-npm ## Typecheck frontend with TypeScript
> cd $(FRONTEND_DIR) && $(NPM) run typecheck

format: format-backend format-frontend ## Format backend and frontend

format-backend: require-venv ## Format backend with Ruff
> cd $(BACKEND_DIR) && $(RUFF) check --fix app tests
> cd $(BACKEND_DIR) && $(RUFF) format app tests

format-frontend: require-npm ## Format frontend if a format script exists
> cd $(FRONTEND_DIR) && $(NPM) run format --if-present

build: build-frontend ## Build production frontend assets

build-frontend: require-npm ## Build frontend production bundle
> cd $(FRONTEND_DIR) && $(NPM) run build

# -----------------------------------------------------------------------------
# CI / verification
# -----------------------------------------------------------------------------

ci: lint typecheck test build ## Run CI-style checks

verify: require-env doctor lint typecheck test build ## Full local verification

precommit: format lint typecheck test build ## Pre-commit quality gate

# -----------------------------------------------------------------------------
# Docker Compose operations
# -----------------------------------------------------------------------------

docker-build: require-env require-docker ## Build Docker images
> $(COMPOSE) build --parallel

docker-up: require-env require-docker ## Start Docker Compose stack
> $(COMPOSE) up --build -d

docker-down: require-docker ## Stop Docker Compose stack
> $(COMPOSE) down

docker-restart: docker-down docker-up ## Restart Docker Compose stack

docker-logs: require-docker ## Tail Docker Compose logs
> $(COMPOSE) logs -f

docker-logs-backend: require-docker ## Tail backend logs
> $(COMPOSE) logs -f backend

docker-logs-frontend: require-docker ## Tail frontend logs
> $(COMPOSE) logs -f frontend

docker-ps: require-docker ## Show Docker Compose service status
> $(COMPOSE) ps

docker-reset: require-docker ## Destructive: stop containers and remove volumes
> @if [ "$(CONFIRM)" != "1" ]; then \
>   echo "This is destructive."; \
>   echo "Run: make docker-reset CONFIRM=1"; \
>   exit 1; \
> fi
> $(COMPOSE) down -v --remove-orphans

docker-reset-full: require-docker ## Destructive: remove containers, volumes, local images
> @if [ "$(CONFIRM)" != "1" ]; then \
>   echo "This is destructive."; \
>   echo "Run: make docker-reset-full CONFIRM=1"; \
>   exit 1; \
> fi
> $(COMPOSE) down -v --rmi local --remove-orphans

fresh-demo: require-env require-docker ## Destructive: reset Docker demo and restart
> @if [ "$(CONFIRM)" != "1" ]; then \
>   echo "This is destructive."; \
>   echo "Run: make fresh-demo CONFIRM=1"; \
>   exit 1; \
> fi
> $(COMPOSE) down -v --remove-orphans
> $(COMPOSE) up --build -d

reset-demo: docker-reset ## Alias for destructive Docker reset

demo: docker-up ## Start full Docker demo stack
> @echo "Frontend: http://localhost:$(FRONTEND_PORT)"
> @echo "Backend:  http://localhost:$(BACKEND_PORT)"
> @echo "API docs: http://localhost:$(BACKEND_PORT)/docs"

db-shell: require-docker ## Open PostgreSQL shell inside Docker
> $(COMPOSE) exec db psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

backend-shell: require-docker ## Open shell in backend container
> $(COMPOSE) exec backend bash

# -----------------------------------------------------------------------------
# API smoke / health
# -----------------------------------------------------------------------------

health: require-curl ## Check backend /health endpoint
> @curl -fsS http://localhost:$(BACKEND_PORT)/health | $(SYS_PYTHON) -m json.tool

ready: require-curl ## Check backend readiness endpoint
> @curl -fsS http://localhost:$(BACKEND_PORT)/api/v1/health/ready | $(SYS_PYTHON) -m json.tool

openapi: require-curl ## Fetch OpenAPI JSON
> @curl -fsS http://localhost:$(BACKEND_PORT)/api/v1/openapi.json | $(SYS_PYTHON) -m json.tool

api-docs: ## Print local OpenAPI docs URL
> @echo "http://localhost:$(BACKEND_PORT)/docs"

frontend-url: ## Print local frontend URL
> @echo "http://localhost:$(FRONTEND_PORT)"

smoke: require-curl ## Basic HTTP smoke check against running backend
> @echo "Checking backend health..."
> @curl -fsS http://localhost:$(BACKEND_PORT)/health >/dev/null
> @echo "Checking OpenAPI..."
> @curl -fsS http://localhost:$(BACKEND_PORT)/api/v1/openapi.json >/dev/null
> @echo "Smoke check passed."

# -----------------------------------------------------------------------------
# Project tree / repo hygiene
# -----------------------------------------------------------------------------

tree: require-venv ## Generate PROJECT_TREE.txt
> PYTHONPATH=$(BACKEND_DIR) $(VENV_PYTHON) scripts/generate_project_tree.py > PROJECT_TREE.txt

check-secrets: ## Scan Git repository for obvious accidental secrets
> @if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
>   echo "Running basic secret scan..."; \
>   git grep -nE "BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*['\"][^'\"]{12,}|secret\s*[:=]\s*['\"][^'\"]{16,}" -- . ':!.env.example' ':!docs' || echo "No obvious secrets found."; \
> else \
>   echo "Not a Git repository; skipping secret scan."; \
> fi

security-check: check-secrets env-warn ## Run basic local security checks

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

clean: clean-python clean-frontend-cache ## Remove caches and build artifacts

clean-python: ## Remove Python caches
> rm -rf .pytest_cache .mypy_cache .ruff_cache
> find . -type d -name '__pycache__' -prune -exec rm -rf {} +
> find . -type f -name '*.pyc' -delete

clean-frontend-cache: ## Remove frontend caches/build output
> rm -rf $(FRONTEND_DIR)/dist
> rm -rf $(FRONTEND_DIR)/node_modules/.vite
> rm -rf $(FRONTEND_DIR)/node_modules/.cache

clean-venv: ## Remove Python virtual environment
> rm -rf $(VENV)

clean-node: ## Remove frontend node_modules
> rm -rf $(FRONTEND_DIR)/node_modules

clean-all: clean clean-venv clean-node ## Destructive: remove caches, venv, node_modules

# -----------------------------------------------------------------------------
# Dependency helpers
# -----------------------------------------------------------------------------

freeze: require-venv ## Print installed Python dependencies
> @$(PIP) freeze

outdated: require-venv ## Show outdated Python and npm dependencies
> @$(PIP) list --outdated || true
> @cd $(FRONTEND_DIR) && $(NPM) outdated || true

audit-frontend: require-npm ## Run npm audit
> @cd $(FRONTEND_DIR) && $(NPM) audit --audit-level=high || true

# -----------------------------------------------------------------------------
# Secret generation helpers
# -----------------------------------------------------------------------------

generate-secret: ## Generate a strong hex secret
> @$(SYS_PYTHON) -c "import secrets; print(secrets.token_hex(64))"

generate-password: ## Generate a strong URL-safe password
> @$(SYS_PYTHON) -c "import secrets; print(secrets.token_urlsafe(24))"