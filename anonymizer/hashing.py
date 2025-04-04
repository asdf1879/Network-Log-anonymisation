import hashlib
import os

SALT = os.urandom(16)  # Generate a unique salt for this session

def hash_with_salt(value):
    """Hashes a value using SHA-256 with a salt."""
    salted_value = SALT + value.encode()
    return hashlib.sha256(salted_value).hexdigest()
