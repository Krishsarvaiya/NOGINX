"""JWT token encoder/decoder using standard python libraries.

Enables secure authentication and Role-Based Access Control (RBAC) 
without external dependencies like PyJWT.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import time

SECRET_KEY = "cybersecurity_soc_secret_2026_key"

def base64url_encode(data: bytes) -> str:
    """Base64 urlsafe encoding without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data_str: str) -> bytes:
    """Base64 urlsafe decoding with restored trailing '=' padding."""
    padding = '=' * (4 - (len(data_str) % 4))
    return base64.urlsafe_b64decode(data_str + padding)


def generate_jwt(payload: dict, secret: str = SECRET_KEY) -> str:
    """Generates an HS256 signed JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    
    signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), signature_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jwt(token: str, secret: str = SECRET_KEY) -> dict | None:
    """Verifies HS256 signed JWT token signature and expiration.
    
    Returns decoded payload if valid, else None.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify signature
        signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_signature = hmac.new(secret.encode('utf-8'), signature_input, hashlib.sha256).digest()
        expected_signature_b64 = base64url_encode(expected_signature)
        
        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            return None
            
        payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
        
        # Check expiration
        if 'exp' in payload and time.time() > payload['exp']:
            return None
            
        return payload
    except Exception:
        return None
