# Rekor verifier

Ahamed Fofana, NYU NetID af4074.
CS-GY 9223, Fall 2026.

This Python CLI checks an artifact's signature and its inclusion in Rekor, saves a checkpoint, and verifies consistency between two checkpoints of the same log tree.
It uses the assignment's [starter code](https://github.com/stupendoussuperpowers/python-rekor-monitor-template).
The CLI and verification helpers include type annotations and automated tests.
Assignment 1 is preserved at commit `df947b8bff383912d7c5da1b70b165af4786999f`.

## Setup

Requires Python 3.11 or newer, Poetry, and TruffleHog.
Cosign is needed only when signing a new artifact.

```bash
poetry install
poetry run pre-commit install
```

Cosign is only needed to sign a new artifact.
The included `artifact.md` and `artifact.bundle` are the files used in the submission screenshots.
`signing-config.json` selects the public Rekor v1 API used by the assignment.

## Verify inclusion

```bash
poetry run python main.py --inclusion 3057814304 --artifact artifact.md
```

The command checks the artifact hash, the signature using the certificate's public key, and the Merkle inclusion proof against the returned root hash.
It exits with an error if a check fails.

## Fetch a checkpoint

```bash
poetry run python main.py -c
```

This prints the active tree ID, size, and root hash and saves the full response to `checkpoint.json`.
Running it again replaces that file with a newer snapshot.

## Verify consistency

The following uses the older checkpoint from the submission screenshots:

```bash
poetry run python main.py --consistency \
  --tree-id 1193050959916656506 \
  --tree-size 2936183602 \
  --root-hash e98bd0ac68d391387783f6b90d10427bed5c97a15e1dd7f14368d5ab7fd7c801
```

The command fetches the latest checkpoint for the same tree and checks the consistency proof using the supplied Merkle verifier.
The newer tree must have more entries for this assignment's demo.
The Merkle checks compare the supplied roots; this CLI does not verify checkpoint signatures or the certificate's identity and trust chain.

## Files

- `main.py`: Rekor CLI implementation.
- `util.py` and `merkle_proof.py`: supplied signature and Merkle verification helpers.
- `scripts/create_artifact.py`: supplied artifact creation script.
- `requirements.txt`: Python dependencies.
- `artifact.md` and `artifact.bundle`: submitted artifact and Cosign bundle.
- `checkpoint.json`: older checkpoint used in the consistency demo.
- `signing-config.json`: Cosign service configuration.
- `root.layout`: supplied in-toto layout used for the written threat analysis.

The screenshots and threat-analysis answers are submitted in the separate PDF.

## Development

On macOS, install Poetry and TruffleHog with `brew install poetry trufflehog`.
After `poetry install`, install the repository hook with `poetry run pre-commit install`.
All Python dependencies, including development tools, are pinned in `poetry.lock`.

```sh
poetry run ruff format .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
poetry run pytest
```

Pytest generates a terminal coverage report and `htmlcov/index.html`.
Coverage must be at least 75% across `main.py`, `merkle_proof.py`, `util.py`, and `scripts/`.
The GitHub Actions workflow runs formatting, lint, type, security, and coverage checks on Python 3.11 and 3.14 for pushes and pull requests.
Tests generate disposable keys locally and stub HTTP responses to exercise success and failure paths without a live Rekor dependency.
The CLI subprocess tests exercise argument parsing, exit codes, and invalid inputs.

## Secret scanning

The pre-commit configuration invokes TruffleHog once per commit against staged changes since HEAD.
It does not replay the full repository history.
`--no-verification` prevents live credential checks, and all detected candidate secrets block the commit.
Test the hook using a disposable repository and synthetic credentials rather than adding secret fixtures to this repository.
Run `poetry run pre-commit run --all-files` to invoke the hook manually; its scan is still limited to staged changes.

## Repository policies

See CONTRIBUTING.md for issue, pull request, style, and testing requirements.
See SECURITY.md for supported versions, vulnerability reporting, and verification limitations.
`.github/CODEOWNERS` assigns repository ownership to @ahamedfo.
The MIT license covers original contributions; the supplied starter code retains its upstream authors' rights.
GitHub's active `Protect main` ruleset requires pull requests and linear history and blocks force pushes and deletion of main.

## Assignment 2 evidence

Preserve tool output from the Assignment 1 commit before applying fixes.
Capture final formatter, linter, mypy, and Bandit output after all fixes, including partner review changes.
Report Halstead metrics for two files before and after the partner review, and include screenshots of the secret scan, coverage, and branch rule in the submission PDF.
The partner review and final measurements after that review remain separate from the individual setup work.
