# Contributing

## Development setup

Install Poetry and TruffleHog, then run:

```sh
poetry install
poetry run pre-commit install
```

## Issues and pull requests

Open an issue with a clear description, affected code lines, reproduction steps, and expected behavior.
Use synthetic data for security examples and report vulnerabilities privately as described in SECURITY.md.
Agree on the intended fix before implementing a review suggestion.
Create a branch and a pull request that references the issue, explains the change, and records validation.
Keep changes focused and preserve the attribution for supplied starter code.
Squash or rebase when merging to preserve linear history.

## Required checks

Use Python 3.11 or newer, annotate function parameters and return values, and format with Ruff.
Run these checks before requesting review:

```sh
poetry run ruff format --check .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
poetry run pytest
poetry run pre-commit run --all-files
```

Tests must cover the behavior changed, including relevant failure paths.
The test suite must contain at least 10 cases and achieve at least 75% statement coverage across the CLI, Merkle helpers, signature helpers, and artifact creation script.
Tests use generated certificates and local HTTP stubs so normal validation does not depend on a live Rekor service.
Keep `poetry.lock` in version control and use `poetry lock` when dependencies change.

## Secret scanning

Install TruffleHog locally and keep it on PATH.
The hook scans staged changes relative to HEAD rather than replaying repository history.
It runs with `--no-verification`, includes unverified detections, and fails on findings.
A passing scan does not guarantee that a file contains no secrets.
