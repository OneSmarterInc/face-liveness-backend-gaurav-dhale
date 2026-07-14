import os
import base64

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # bytes, standard for GCM


class EmbeddingCryptoError(Exception):
    pass


def _get_key() -> bytes:

    key_b64 = os.environ.get("AES_KEY")
    if not key_b64:
        raise EmbeddingCryptoError("AES_KEY is not set")
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise EmbeddingCryptoError("AES_KEY must decode to 32 bytes")
    return key


def encrypt_embedding(embedding: np.ndarray, user_id: str) -> bytes:
    aesgcm = AESGCM(_get_key())
    nonce = os.urandom(NONCE_SIZE)
    plaintext = embedding.astype(np.float32).tobytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=user_id.encode())
    return nonce + ciphertext


def decrypt_embedding(blob: bytes, user_id: str) -> np.ndarray:
    aesgcm = AESGCM(_get_key())
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=user_id.encode())
    except Exception as e:
        raise EmbeddingCryptoError("Embedding decryption/authentication failed") from e
    return np.frombuffer(plaintext, dtype=np.float32)