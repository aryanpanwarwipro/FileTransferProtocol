import hashlib, os, base64
 
def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with random salt.
    Returns 'salt$hash', both base64 encoded.
    """
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100_000
    )
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(hashed).decode()
 
def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a plain password against a stored 'salt$hash'.
    """
    try:
        salt_b64, hash_b64 = stored_hash.split("$", 1)
        salt = base64.b64decode(salt_b64)
        hash_bytes = base64.b64decode(hash_b64)
        test_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100_000
        )
        return test_hash == hash_bytes
    except Exception:
        return False