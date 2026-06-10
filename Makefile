.PHONY: install clean test lint run docker-build docker-run help

help:
	@echo "SSRF Auditor v2.0 - Makefile"
	@echo "============================"
	@echo "install       Install dependencies"
	@echo "clean         Clean build artifacts"
	@echo "test          Run tests"
	@echo "lint          Run linters"
	@echo "typecheck     Run mypy type checking"
	@echo "run           Run the auditor (set URL=<target>)"
	@echo "docker-build  Build Docker image"
	@echo "docker-run    Run in Docker (set URL=<target>)"

install:
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -e .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist .coverage coverage.xml 2>/dev/null || true

test:
	pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/
	black --check src/ tests/

typecheck:
	mypy src/

format:
	black src/ tests/
	ruff check --fix src/ tests/

run:
	python -m src.main -u "$(URL)" $(ARGS)

docker-build:
	docker build -t ssrf-auditor:latest .

docker-run:
	docker run --rm -v "$$(pwd)/results:/app/results" -v "$$(pwd)/config.yaml:/app/config.yaml" ssrf-auditor:latest -u "$(URL)" $(ARGS)

docker-shell:
	docker run --rm -it --entrypoint /bin/bash ssrf-auditor:latest
