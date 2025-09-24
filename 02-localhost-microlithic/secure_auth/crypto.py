"""PKCE and cryptographic helper functions."""
import secrets
import base64
import hashlib

def generate_code_verifier() -> str:
    """Generate a cryptographically secure code verifier for PKCE."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(code_verifier: str) -> str:
    """Generate code challenge from verifier using SHA256."""
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def generate_state() -> str:
    """Generate a secure state parameter for CSRF protection."""
    return secrets.token_urlsafe(32)

def generate_nonce() -> str:
    """Generate a secure nonce for ID token validation."""
    return secrets.token_urlsafe(32)
