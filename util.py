import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def scrypt(salt: bytes, pwd: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(pwd)


def hkdf(n: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"salt", info=b"info"
    ).derive(n.to_bytes(2048))


def ae(k: bytes, p: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, p, None)


def ad(k: bytes, nc: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce, ciphertext = nc[:12], nc[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def u64(b64: str) -> bytes:
    return base64.b64decode(b64)
