"""
Simple symmetric encryption wrapper:
- Uses cryptography's Fernet (AES + HMAC under the hood)
- KEY is derived from a fixed password + SALT using PBKDF2
    As long as server and client files are identical, communication will succeed
"""

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



PASSPHRASE = b"my_super_secret_chatroom_password"
SALT = b"static_salt_1234"  # 16 bytes fixed salt, sufficient for classroom project


def _derive_key() -> bytes:
    """Derive a 32-byte key from PASSPHRASE + SALT, and convert to Fernet's required base64 format."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=390000,
    )
    key = kdf.derive(PASSPHRASE)
    return base64.urlsafe_b64encode(key)


_KEY = _derive_key()
_cipher = Fernet(_KEY)


def encrypt_msg(plaintext: str) -> bytes:
    """Input plaintext string, output ciphertext bytes, for use with socket.sendall()."""
    if not isinstance(plaintext, str):
        raise TypeError("encrypt_msg expects str")
    return _cipher.encrypt(plaintext.encode("utf-8"))


def decrypt_msg(token: bytes) -> str:
    """Input ciphertext bytes received from socket.recv(), output decrypted string."""
    if not isinstance(token, (bytes, bytearray)):
        raise TypeError("decrypt_msg expects bytes")
    return _cipher.decrypt(token).decode("utf-8")
