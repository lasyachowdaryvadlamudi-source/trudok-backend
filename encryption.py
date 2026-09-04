import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from config import settings

logger = logging.getLogger("trudok.encryption")

def get_fernet_instance() -> Fernet:
    """
    Returns a configured Fernet cipher for field-level PII encryption at rest.
    Uses ENCRYPTION_KEY from environment or derives a deterministic key from API_KEY in development.
    """
    raw_key = os.getenv("ENCRYPTION_KEY")
    if not raw_key:
        # Deterministically derive 32-byte url-safe base64 key from API_KEY for dev consistency
        derived = hashlib.sha256(settings.API_KEY.encode("utf-8")).digest()
        raw_key = base64.urlsafe_b64encode(derived).decode("utf-8")
    
    try:
        return Fernet(raw_key.encode("utf-8") if isinstance(raw_key, str) else raw_key)
    except Exception as e:
        logger.error(f"Failed to initialize Fernet encryption cipher: {e}")
        # Fallback key
        key = Fernet.generate_key()
        return Fernet(key)

_fernet = get_fernet_instance()

def encrypt_pii(plaintext: str) -> str:
    """
    Encrypts sensitive PII (Full Name, Document Number, Date of Birth) before database storage.
    Returns URL-safe encrypted ciphertext prefixed with 'ENC::'.
    """
    if not plaintext or plaintext == "UNKNOWN":
        return plaintext
    if str(plaintext).startswith("ENC::"):
        return plaintext # Already encrypted
    try:
        ciphertext = _fernet.encrypt(str(plaintext).encode("utf-8")).decode("utf-8")
        return f"ENC::{ciphertext}"
    except Exception as e:
        logger.warning(f"PII encryption failed: {e}")
        return plaintext

def decrypt_pii(ciphertext: str) -> str:
    """
    Decrypts encrypted PII for authorized presentation.
    """
    if not ciphertext or not str(ciphertext).startswith("ENC::"):
        return ciphertext # Plaintext or none
    try:
        raw_token = str(ciphertext)[5:] # Remove 'ENC::' prefix
        return _fernet.decrypt(raw_token.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"PII decryption failed: {e}")
        return "[ENCRYPTED PII]"
