import hashlib
from passlib.context import CryptContext

# Configure CryptContext with Argon2 and Bcrypt
# Uses argon2 by default (no 72-byte truncation) with bcrypt support
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto"
)

def pre_hash_sha256(secret: str) -> str:
    """
    Standard Security Mitigation:
    Pre-hashes inputs with SHA-256 before bcrypt/argon2 hashing to eliminate bcrypt's
    silent 72-byte truncation vulnerability for arbitrary length passwords and API keys.
    """
    if secret is None:
        secret = ""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()

def hash_secret(secret: str) -> str:
    """
    Safely hashes passwords or API keys.
    Applies SHA-256 pre-hashing before passing to password hashing algorithm.
    """
    pre_hashed = pre_hash_sha256(secret)
    return pwd_context.hash(pre_hashed)

def verify_secret(plain_secret: str, hashed_secret: str) -> bool:
    """
    Safely verifies plaintext secret against hashed secret.
    """
    if not plain_secret or not hashed_secret:
        return False
    pre_hashed = pre_hash_sha256(plain_secret)
    return pwd_context.verify(pre_hashed, hashed_secret)
