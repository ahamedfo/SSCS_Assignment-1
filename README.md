# Software Supply Chain Security - Assignment 1

Ahamed Fofana, NYU NetID af4074.
CS-GY 9223, Fall 2026.

This Python CLI checks an artifact's signature and its inclusion in Rekor, saves a checkpoint, and verifies consistency between two checkpoints of the same log tree.
It uses the assignment's [starter code](https://github.com/stupendoussuperpowers/python-rekor-monitor-template).
The implementation changes are in `main.py`; the supplied verification helpers are unchanged.

## Setup

Tested with Python 3.13 and Cosign 3.1.3 on macOS.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Cosign is only needed to sign a new artifact.
The included `artifact.md` and `artifact.bundle` are the files used in the submission screenshots.
`signing-config.json` selects the public Rekor v1 API used by the assignment.

## Verify inclusion

```bash
python main.py --inclusion 3057814304 --artifact artifact.md
```

The command checks the artifact hash, the signature using the certificate's public key, and the Merkle inclusion proof against the returned root hash.
It exits with an error if a check fails.

## Fetch a checkpoint

```bash
python main.py -c
```

This prints the active tree ID, size, and root hash and saves the full response to `checkpoint.json`.
Running it again replaces that file with a newer snapshot.

## Verify consistency

The following uses the older checkpoint from the submission screenshots:

```bash
python main.py --consistency \
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
