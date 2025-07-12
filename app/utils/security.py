import re
import ipaddress
from typing import Optional, List
from datetime import datetime, timedelta
import secrets
import uuid
from fastapi import Request
import logging

logger = logging.getLogger(__name__)


def sanitize_string(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize string input to prevent injection attacks.
    
    Args:
        input_string: String to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not input_string:
        return ""
    
    # Truncate to max length
    input_string = input_string[:max_length]
    
    # Remove null bytes
    input_string = input_string.replace('\x00', '')
    
    # Remove control characters except newline and tab
    cleaned = ''.join(char for char in input_string if char == '\n' or char == '\t' or not ord(char) < 32)
    
    return cleaned.strip()


def is_valid_uuid(uuid_string: str) -> bool:
    """
    Check if string is a valid UUID.
    
    Args:
        uuid_string: String to validate
        
    Returns:
        True if valid UUID, False otherwise
    """
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, AttributeError):
        return False


def is_valid_base64(string: str) -> bool:
    """
    Check if string is valid base64.
    
    Args:
        string: String to validate
        
    Returns:
        True if valid base64, False otherwise
    """
    if not string:
        return False
    
    # Base64 pattern
    pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    
    # Check pattern and length is multiple of 4
    return bool(pattern.match(string)) and len(string) % 4 == 0


def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request, handling proxies.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address
    """
    # Check X-Forwarded-For header first (for proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Get the first IP in the chain
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        # Fall back to direct connection
        client_ip = request.client.host if request.client else "unknown"
    
    # Validate IP address
    try:
        ipaddress.ip_address(client_ip)
        return client_ip
    except ValueError:
        return "unknown"


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging.
    
    Args:
        data: Sensitive data to mask
        visible_chars: Number of characters to keep visible
        
    Returns:
        Masked string
    """
    if not data or len(data) <= visible_chars * 2:
        return "****"
    
    return f"{data[:visible_chars]}{'*' * (len(data) - visible_chars * 2)}{data[-visible_chars:]}"


def generate_correlation_id() -> uuid.UUID:
    """Generate a unique correlation ID for request tracking."""
    return uuid.uuid4()


def is_rate_limited(
    key: str,
    requests: int,
    window_seconds: int,
    storage: dict
) -> tuple[bool, int]:
    """
    Simple in-memory rate limiting check.
    
    Args:
        key: Unique key for rate limiting (e.g., user ID or IP)
        requests: Maximum number of requests allowed
        window_seconds: Time window in seconds
        storage: Dictionary to store rate limit data
        
    Returns:
        Tuple of (is_limited, retry_after_seconds)
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=window_seconds)
    
    # Clean old entries
    if key in storage:
        storage[key] = [ts for ts in storage[key] if ts > window_start]
    else:
        storage[key] = []
    
    # Check if rate limited
    if len(storage[key]) >= requests:
        oldest_request = min(storage[key])
        retry_after = int((oldest_request + timedelta(seconds=window_seconds) - now).total_seconds())
        return True, max(retry_after, 1)
    
    # Add current request
    storage[key].append(now)
    return False, 0


def hash_data(data: bytes, algorithm: str = "sha256") -> str:
    """
    Hash data using specified algorithm.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha512, etc.)
        
    Returns:
        Hex-encoded hash
    """
    # Use cryptography library instead of hashlib to avoid BoringSSL issues
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    try:
        if algorithm == "sha256":
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif algorithm == "sha512":
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        digest.update(data)
        return digest.finalize().hex()
    except Exception as e:
        logger.error(f"Hash operation failed: {str(e)}")
        # Fallback to a simple implementation
        import hashlib
        if algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
    """
    return secrets.compare_digest(a.encode(), b.encode())


def validate_key_purpose(purpose: str) -> bool:
    """
    Validate key purpose string.
    
    Args:
        purpose: Key purpose to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not purpose:
        return True  # Purpose is optional
    
    # Allow alphanumeric, spaces, hyphens, and underscores
    pattern = re.compile(r'^[a-zA-Z0-9_\-\s]+$')
    return bool(pattern.match(purpose)) and len(purpose) <= 100


def clean_user_agent(user_agent: Optional[str]) -> str:
    """
    Clean and truncate user agent string.
    
    Args:
        user_agent: User agent string
        
    Returns:
        Cleaned user agent
    """
    if not user_agent:
        return "unknown"
    
    # Remove any control characters and truncate
    cleaned = sanitize_string(user_agent, max_length=500)
    return cleaned or "unknown"