import base64
import hashlib
import json
import runpy
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import main
import util
from merkle_proof import (
    DefaultHasher as H,
)
from merkle_proof import (
    RootMismatchError,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signed_entry(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.invalid")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    data = b"test artifact\n"
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(data)
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
    body = {
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(data).hexdigest(),
                }
            },
            "signature": {
                "content": base64.b64encode(signature).decode(),
                "publicKey": {
                    "content": base64.b64encode(
                        cert.public_bytes(serialization.Encoding.PEM)
                    ).decode()
                },
            },
        }
    }
    encoded = base64.b64encode(json.dumps(body).encode()).decode()
    entry = {
        "logIndex": 0,
        "body": encoded,
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "hashes": [],
                "rootHash": compute_leaf_hash(encoded),
            }
        },
    }
    return artifact, entry


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main.main()


def respond(monkeypatch, payload):
    response = Mock()
    response.json.return_value = payload
    get = Mock(return_value=response)
    monkeypatch.setattr(main.requests, "get", get)
    return get


@pytest.mark.parametrize(
    "args,code,message",
    [
        (["--help"], 0, "Rekor Verifier"),
        (["--inclusion", "0"], 2, "requires --artifact"),
        (["--consistency"], 2, "requires --tree-id"),
        (["--consistency", "--tree-id", "1"], 2, "requires --tree-size"),
        (
            ["--consistency", "--tree-id", "1", "--tree-size", "1"],
            2,
            "requires --root-hash",
        ),
        (["--inclusion", "-1", "--artifact", "artifact.md"], 1, "non-negative"),
        (["--inclusion", "0", "--artifact", "missing-artifact"], 1, "existing file"),
    ],
)
def test_cli_subprocess(args, code, message):
    process = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert process.returncode == code
    assert message in process.stdout + process.stderr


def test_checkpoint_cli_saves_full_response(monkeypatch, tmp_path, capsys):
    checkpoint = {
        "treeID": "1",
        "treeSize": 2,
        "rootHash": "ab" * 32,
        "signedTreeHead": "signature",
        "inactiveShards": [],
    }
    get = respond(monkeypatch, checkpoint)
    monkeypatch.chdir(tmp_path)
    invoke(monkeypatch, "-c", "-d")
    assert json.loads((tmp_path / "checkpoint.json").read_text()) == checkpoint
    assert "Saved full checkpoint" in capsys.readouterr().out
    get.assert_called_once_with("https://rekor.sigstore.dev/api/v1/log", timeout=30)


@pytest.mark.parametrize(
    "error", [requests.Timeout("timeout"), ValueError("invalid JSON")]
)
def test_checkpoint_cli_network_and_payload_errors(
    monkeypatch, tmp_path, capsys, error
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "get_latest_checkpoint", Mock(side_effect=error))
    with pytest.raises(SystemExit) as raised:
        invoke(monkeypatch, "-c")
    assert raised.value.code == 1
    assert "Checkpoint fetch failed" in capsys.readouterr().err
    assert not (tmp_path / "checkpoint.json").exists()


def test_inclusion_cli_valid_signature_and_proof(monkeypatch, signed_entry, capsys):
    artifact, entry = signed_entry
    respond(monkeypatch, {"entry-id": entry})
    invoke(monkeypatch, "--inclusion", "0", "--artifact", str(artifact), "-d")
    assert "Inclusion verification successful" in capsys.readouterr().out
    assert main.get_verification_proof(0) == entry["verification"]["inclusionProof"]


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("artifact", "hash does not match"),
        ("signature", "Signature is invalid"),
        ("proof", "does not match expected root"),
        ("algorithm", "Expected a SHA-256"),
    ],
)
def test_inclusion_cli_rejects_tampering(
    monkeypatch, signed_entry, capsys, mutation, expected
):
    artifact, entry = signed_entry
    body = json.loads(base64.b64decode(entry["body"]))
    if mutation == "artifact":
        artifact.write_bytes(b"changed artifact")
    elif mutation == "signature":
        body["spec"]["signature"]["content"] = base64.b64encode(
            b"invalid signature"
        ).decode()
    elif mutation == "algorithm":
        body["spec"]["data"]["hash"]["algorithm"] = "sha1"
    else:
        entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    entry["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    respond(monkeypatch, {"entry-id": entry})
    with pytest.raises(SystemExit) as raised:
        invoke(monkeypatch, "--inclusion", "0", "--artifact", str(artifact))
    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert expected in captured.err
    assert "Inclusion verification successful" not in captured.out


@pytest.mark.parametrize("payload", [{}, {"a": {}, "b": {}}])
def test_log_entry_requires_exactly_one_result(monkeypatch, payload):
    respond(monkeypatch, payload)
    with pytest.raises(ValueError, match="exactly one"):
        main.get_log_entry(0)


def test_log_entry_http_error(monkeypatch):
    get = respond(monkeypatch, {})
    get.return_value.raise_for_status.side_effect = requests.HTTPError("503")
    with pytest.raises(requests.HTTPError):
        main.get_log_entry(0)


def test_consistency_cli_growth_in_inactive_shard(monkeypatch, capsys):
    a, b = H.hash_leaf(b"a"), H.hash_leaf(b"b")
    new_root = H.hash_children(a, b).hex()
    checkpoint = {
        "treeID": "2",
        "inactiveShards": [{"treeID": "1", "treeSize": 2, "rootHash": new_root}],
    }
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: checkpoint)
    get = respond(monkeypatch, {"hashes": [b.hex()]})
    invoke(
        monkeypatch,
        "--consistency",
        "--tree-id",
        "1",
        "--tree-size",
        "1",
        "--root-hash",
        a.hex(),
    )
    assert "New entries: 1" in capsys.readouterr().out
    assert get.call_args.kwargs["params"] == {
        "firstSize": 1,
        "lastSize": 2,
        "treeID": "1",
    }


@pytest.mark.parametrize(
    "previous,latest,message",
    [
        ({}, {}, "older checkpoint"),
        ({"treeID": "abc", "treeSize": 1, "rootHash": "00" * 32}, {}, "only digits"),
        ({"treeID": "1", "treeSize": 0, "rootHash": "00" * 32}, {}, "positive"),
        ({"treeID": "1", "treeSize": 1, "rootHash": "00"}, {}, "32-byte"),
        (
            {"treeID": "1", "treeSize": 1, "rootHash": "00" * 32},
            {"treeID": "2"},
            "supplied tree ID",
        ),
        (
            {"treeID": "1", "treeSize": 3, "rootHash": "00" * 32},
            {"treeID": "1", "treeSize": 2},
            "exceeds",
        ),
        (
            {"treeID": "1", "treeSize": 1, "rootHash": "00" * 32},
            {"treeID": "1", "treeSize": 1, "rootHash": "00" * 32},
            "not grown",
        ),
        (
            {"treeID": "1", "treeSize": 1, "rootHash": "00" * 32},
            {"treeID": "1", "treeSize": 1, "rootHash": "11" * 32},
            "different root",
        ),
    ],
)
def test_consistency_rejects_bad_checkpoints(monkeypatch, previous, latest, message):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: latest)
    with pytest.raises(ValueError, match=message):
        main.consistency(previous)


def test_consistency_cli_reports_failure(monkeypatch, capsys):
    with pytest.raises(SystemExit) as raised:
        invoke(
            monkeypatch,
            "--consistency",
            "--tree-id",
            "bad",
            "--tree-size",
            "1",
            "--root-hash",
            "00" * 32,
        )
    assert raised.value.code == 1
    assert "Consistency verification failed" in capsys.readouterr().err


def test_hashing_matches_rfc6962():
    assert H.empty_root() == hashlib.sha256(b"").digest()
    assert H.hash_leaf(b"a") == hashlib.sha256(b"\x00a").digest()
    assert H.hash_children(b"a", b"b") == hashlib.sha256(b"\x01ab").digest()
    assert compute_leaf_hash(base64.b64encode(b"a").decode()) == H.hash_leaf(b"a").hex()


def test_inclusion_both_sides_of_two_leaf_tree():
    a, b = H.hash_leaf(b"a"), H.hash_leaf(b"b")
    root = H.hash_children(a, b).hex()
    verify_inclusion(H, 0, 2, a.hex(), [b.hex()], root)
    verify_inclusion(H, 1, 2, b.hex(), [a.hex()], root)


@pytest.mark.parametrize(
    "index,size,leaf,proof,message",
    [
        (1, 1, b"x" * 32, [], "beyond size"),
        (0, 1, b"x", [], "unexpected size"),
        (0, 2, b"x" * 32, [], "wrong proof size"),
    ],
)
def test_invalid_inclusion_structure(index, size, leaf, proof, message):
    with pytest.raises(ValueError, match=message):
        root_from_inclusion_proof(H, index, size, leaf, proof)


def test_consistency_three_to_four_leaves():
    a, b, c, d = [H.hash_leaf(value) for value in (b"a", b"b", b"c", b"d")]
    ab = H.hash_children(a, b)
    old_root = H.hash_children(ab, c)
    root = H.hash_children(ab, H.hash_children(c, d))
    verify_consistency(
        H, 3, 4, [c.hex(), d.hex(), ab.hex()], old_root.hex(), root.hex()
    )


@pytest.mark.parametrize(
    "first,last,proof,message",
    [
        (2, 1, [], "size2"),
        (1, 1, ["00" * 32], "not empty"),
        (0, 1, ["00" * 32], "expected empty"),
        (1, 2, [], "empty bytearray_proof"),
        (1, 2, ["00" * 32, "00" * 32], "wrong bytearray_proof size"),
    ],
)
def test_invalid_consistency_structure(first, last, proof, message):
    with pytest.raises(ValueError, match=message):
        verify_consistency(H, first, last, proof, "00" * 32, "00" * 32)


def test_consistency_empty_and_equal_trees():
    root = H.hash_leaf(b"a").hex()
    verify_consistency(H, 0, 1, [], H.empty_root().hex(), root)
    verify_consistency(H, 1, 1, [], root, root)
    with pytest.raises(RootMismatchError, match="does not match"):
        verify_consistency(H, 1, 1, [], root, "00" * 32)


def test_certificate_and_wrong_key_types(signed_entry):
    _, entry = signed_entry
    body = json.loads(base64.b64decode(entry["body"]))
    pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    assert b"BEGIN PUBLIC KEY" in util.extract_public_key(pem)
    with pytest.raises(ValueError):
        util.extract_public_key(b"not a certificate")
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError, match="elliptic curve"):
        util.verify_artifact_signature(b"signature", public, "unused")


def test_artifact_creation_script(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["create_artifact.py", "af4074"])
    runpy.run_path(str(ROOT / "scripts/create_artifact.py"), run_name="__main__")
    assert (tmp_path / "artifact.md").read_text().strip() == "af4074"


def test_artifact_creation_script_requires_netid(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["create_artifact.py"])
    with pytest.raises(SystemExit, match="NETID"):
        runpy.run_path(str(ROOT / "scripts/create_artifact.py"), run_name="__main__")
    assert not (tmp_path / "artifact.md").exists()


def test_main_module_entrypoint_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--help"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(ROOT / "main.py"), run_name="__main__")
    assert raised.value.code == 0
    assert "Rekor Verifier" in capsys.readouterr().out


def run_cli_with_responses(tmp_path, args, responses):
    """Run the actual CLI with controlled HTTP replies and an isolated directory."""
    import os

    harness = tmp_path / "http_stub"
    harness.mkdir(exist_ok=True)
    payload = harness / "responses.json"
    payload.write_text(json.dumps(responses))
    (harness / "sitecustomize.py").write_text(
        "import json, os\n"
        "from pathlib import Path\n"
        "import requests\n"
        "class Response:\n"
        "    def __init__(self, url): self.url = url\n"
        "    def raise_for_status(self): pass\n"
        "    def json(self):\n"
        '        return json.loads(Path(os.environ["REVIEW_HTTP_RESPONSES"]).read_text())[self.url]\n'
        "def get(url, **kwargs): return Response(url)\n"
        "requests.get = get\n"
    )
    env = os.environ.copy()
    env.update(
        PYTHONPATH=str(harness),
        REVIEW_HTTP_RESPONSES=str(payload),
        PYTHONDONTWRITEBYTECODE="1",
    )
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_cli_rejects_returned_entry_with_wrong_index(tmp_path, signed_entry):
    artifact, entry = signed_entry
    entry["logIndex"] = 1
    result = run_cli_with_responses(
        tmp_path,
        ["--inclusion", "0", "--artifact", str(artifact)],
        {"https://rekor.sigstore.dev/api/v1/log/entries": {"entry": entry}},
    )
    assert result.returncode == 1
    assert "does not match the requested index" in result.stderr
    assert "verification successful" not in result.stdout.lower()


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["-c", "--inclusion", "0"],
        ["-c", "--consistency"],
        ["--inclusion", "0", "--consistency"],
    ],
)
def test_cli_requires_one_action_before_any_side_effect(tmp_path, args):
    result = run_cli_with_responses(
        tmp_path,
        args,
        {
            "https://rekor.sigstore.dev/api/v1/log": {
                "treeID": "1",
                "treeSize": 1,
                "rootHash": "11" * 32,
            }
        },
    )
    assert result.returncode == 2
    expected = "required" if not args else "not allowed"
    assert expected in result.stderr
    assert not list(tmp_path.glob("checkpoint*.json"))
    assert "verification successful" not in result.stdout.lower()
