from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def extract_public_key(cert: bytes) -> bytes:

    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    public_key = certificate.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> None:

    loaded_key = load_pem_public_key(public_key)
    if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected an elliptic curve public key")
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        loaded_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
    except Exception as e:
        print("Exception in verifying artifact signature:", e)
