import argparse
import base64
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import requests

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature


def get_log_entry(log_index: int, debug: bool = False) -> dict[str, Any]:
    if log_index < 0:
        raise ValueError("Log index must be non-negative")

    response = requests.get(
        "https://rekor.sigstore.dev/api/v1/log/entries",
        params={"logIndex": log_index},
        timeout=30,
    )
    response.raise_for_status()

    entries = response.json()
    if len(entries) != 1:
        raise ValueError("Expected exactly one log entry")

    entry = next(iter(entries.values()))
    if entry["logIndex"] != log_index:
        raise ValueError("Returned log index does not match the requested index")
    return entry


def get_verification_proof(log_index: int, debug: bool = False) -> dict[str, Any]:
    entry = get_log_entry(log_index, debug)
    return entry["verification"]["inclusionProof"]


def inclusion(log_index: int, artifact_filepath: str, debug: bool = False) -> None:
    artifact = Path(artifact_filepath)
    if not artifact.is_file():
        raise ValueError("Artifact must be an existing file")

    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"], validate=True))
    recorded_hash = body["spec"]["data"]["hash"]
    if recorded_hash["algorithm"] != "sha256":
        raise ValueError("Expected a SHA-256 artifact hash")
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != recorded_hash["value"]:
        raise ValueError("Artifact hash does not match the Rekor record")

    signature_data = body["spec"]["signature"]
    signature = base64.b64decode(signature_data["content"], validate=True)
    certificate = base64.b64decode(
        signature_data["publicKey"]["content"], validate=True
    )
    public_key = extract_public_key(certificate)

    # The supplied helper prints failures instead of raising them.
    # Capture its diagnostics so a failed signature cannot report success.
    diagnostics = io.StringIO()
    with redirect_stdout(diagnostics):
        verify_artifact_signature(signature, public_key, artifact_filepath)
    if diagnostics.getvalue():
        raise ValueError(diagnostics.getvalue().strip())
    print("Artifact signature is valid")

    proof = entry["verification"]["inclusionProof"]
    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        compute_leaf_hash(entry["body"]),
        proof["hashes"],
        proof["rootHash"],
        debug=debug,
    )
    print("Inclusion proof is valid")
    print("Inclusion verification successful")


def get_latest_checkpoint(debug: bool = False) -> dict[str, Any]:
    response = requests.get("https://rekor.sigstore.dev/api/v1/log", timeout=30)
    response.raise_for_status()
    return response.json()


def consistency(prev_checkpoint: dict[str, Any], debug: bool = False) -> None:
    if not prev_checkpoint:
        raise ValueError("An older checkpoint is required")
    tree_id = str(prev_checkpoint["treeID"])
    old_size = prev_checkpoint["treeSize"]
    old_root = prev_checkpoint["rootHash"]
    if not tree_id.isdigit():
        raise ValueError("Tree ID must contain only digits")
    if old_size < 1:
        raise ValueError("Older tree size must be positive")
    if len(bytes.fromhex(old_root)) != DefaultHasher.size():
        raise ValueError("Root hash must be a 32-byte hexadecimal SHA-256 hash")

    log_info = get_latest_checkpoint(debug)
    # Proofs must compare two checkpoints of the same tree, even after rotation.
    trees = [log_info, *log_info.get("inactiveShards", [])]
    latest = next((tree for tree in trees if str(tree["treeID"]) == tree_id), None)
    if latest is None:
        raise ValueError("Rekor did not return a checkpoint for the supplied tree ID")
    new_size = latest["treeSize"]
    if old_size > new_size:
        raise ValueError("Older tree size exceeds the latest tree size")
    if old_size == new_size:
        if bytes.fromhex(old_root) != bytes.fromhex(latest["rootHash"]):
            raise ValueError("Equal tree sizes have different root hashes")
        raise ValueError(
            "The tree has not grown; retry later with distinct checkpoints"
        )

    response = requests.get(
        "https://rekor.sigstore.dev/api/v1/log/proof",
        params={"firstSize": old_size, "lastSize": new_size, "treeID": tree_id},
        timeout=30,
    )
    response.raise_for_status()
    proof = response.json()
    verify_consistency(
        DefaultHasher,
        old_size,
        new_size,
        proof["hashes"],
        old_root,
        latest["rootHash"],
    )
    print(f"Tree ID: {tree_id}")
    print(f"Older tree size: {old_size}")
    print(f"Latest tree size: {new_size}")
    print(f"New entries: {new_size - old_size}")
    print("Consistency verification successful")


def main() -> None:
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    actions.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    actions.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    parser.add_argument(
        "--output", type=Path, help="Save a checkpoint to a new file at this path"
    )
    args = parser.parse_args()
    if args.output is not None and not args.checkpoint:
        parser.error("--output requires --checkpoint")
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        try:
            checkpoint = get_latest_checkpoint(debug)
            summary = {
                key: checkpoint[key] for key in ("treeID", "treeSize", "rootHash")
            }
            tree_id = str(checkpoint["treeID"])
            tree_size = checkpoint["treeSize"]
            if not tree_id.isascii() or not tree_id.isdigit():
                raise ValueError("Checkpoint tree ID must contain only ASCII digits")
            if type(tree_size) is not int or tree_size <= 0:
                raise ValueError("Checkpoint tree size must be a positive integer")
            destination = args.output or Path(f"checkpoint-{tree_id}-{tree_size}.json")
            contents = json.dumps(checkpoint, indent=4) + "\n"
            try:
                with destination.open("x", encoding="utf-8") as output:
                    output.write(contents)
            except FileExistsError:
                parser.exit(
                    1,
                    f"Checkpoint file already exists: {destination}; "
                    "use --output with a new path.\n",
                )
        except (ValueError, KeyError, OSError, requests.RequestException) as error:
            parser.exit(1, f"Checkpoint fetch failed: {error}\n")
        print(json.dumps(summary, indent=4))
        print(f"Saved full checkpoint to {destination}")
    elif args.inclusion is not None:
        if not args.artifact:
            parser.error("--inclusion requires --artifact")
        try:
            inclusion(args.inclusion, args.artifact, debug)
        except (
            ValueError,
            KeyError,
            OSError,
            requests.RequestException,
            RootMismatchError,
        ) as error:
            parser.exit(1, f"Inclusion verification failed: {error}\n")
    elif args.consistency:
        if not args.tree_id:
            parser.error("--consistency requires --tree-id")
        if args.tree_size is None:
            parser.error("--consistency requires --tree-size")
        if not args.root_hash:
            parser.error("--consistency requires --root-hash")

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        try:
            consistency(prev_checkpoint, debug)
        except (
            ValueError,
            KeyError,
            OSError,
            requests.RequestException,
            RootMismatchError,
        ) as error:
            parser.exit(1, f"Consistency verification failed: {error}\n")


if __name__ == "__main__":
    main()
