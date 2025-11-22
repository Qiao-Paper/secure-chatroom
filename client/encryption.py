import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


PASSPHRASE = b"my_super_secret_chatroom_password"
SALT = b"static_salt_1234"


def _derive_key() -> bytes:
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
    if not isinstance(plaintext, str):
        raise TypeError("encrypt_msg expects str")
    return _cipher.encrypt(plaintext.encode("utf-8"))


def decrypt_msg(token: bytes) -> str:
    if not isinstance(token, (bytes, bytearray)):
        raise TypeError("decrypt_msg expects bytes")
    return _cipher.decrypt(token).decode("utf-8")
