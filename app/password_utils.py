import bcrypt


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt and return a UTF-8 string."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash string."""
    return bcrypt.checkpw(password.encode(), hashed.encode())
