from typing import Optional
from fastapi import Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
import uuid

from app.database import get_db
from app.utils.security import get_client_ip, clean_user_agent, generate_correlation_id
from app.config import settings


async def get_correlation_id(request: Request) -> uuid.UUID:
    """
    Get or generate correlation ID for request tracking.
    
    Args:
        request: FastAPI request
        
    Returns:
        Correlation ID
    """
    # Check if correlation ID is already in headers
    correlation_id = request.headers.get("X-Correlation-ID")
    
    if correlation_id:
        try:
            return uuid.UUID(correlation_id)
        except ValueError:
            pass
    
    # Generate new correlation ID
    return generate_correlation_id()


async def get_request_info(request: Request) -> dict:
    """
    Extract request information for logging and auditing.
    
    Args:
        request: FastAPI request
        
    Returns:
        Dictionary with request information
    """
    return {
        "ip_address": get_client_ip(request),
        "user_agent": clean_user_agent(request.headers.get("User-Agent")),
        "method": request.method,
        "path": request.url.path,
        "query_params": dict(request.query_params)
    }


class RateLimiter:
    """Rate limiting dependency"""
    
    def __init__(self):
        self.storage = {}
    
    async def __call__(self, request: Request):
        """Check rate limits by IP address since authentication is disabled"""
        from app.utils.security import is_rate_limited, get_client_ip
        
        # Use IP address as rate limit key
        ip_address = get_client_ip(request)
        key = f"ip:{ip_address}"
        
        # Check rate limit
        is_limited, retry_after = is_rate_limited(
            key=key,
            requests=settings.RATE_LIMIT_REQUESTS,
            window_seconds=settings.RATE_LIMIT_WINDOW,
            storage=self.storage
        )
        
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)}
            )


# Rate limiter instance
rate_limiter = RateLimiter()


async def validate_content_length(request: Request):
    """
    Validate request content length.
    
    Args:
        request: FastAPI request
        
    Raises:
        HTTPException: If content length exceeds limit
    """
    content_length = request.headers.get("Content-Length")
    
    if content_length and int(content_length) > settings.MAX_REQUEST_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request size exceeds maximum allowed size of {settings.MAX_REQUEST_SIZE} bytes"
        )


async def check_hsm_availability():
    """
    Check if HSM is available.
    
    Raises:
        HTTPException: If HSM is not available
    """
    from app.hsm.manager import hsm_manager
    
    try:
        info = hsm_manager.get_hsm_info()
        if not info.get("connected", False):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="HSM service is not available"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"HSM service error: {str(e)}"
        )


class PaginationParams:
    """Common pagination parameters"""
    
    def __init__(
        self,
        page: int = 1,
        page_size: int = 50
    ):
        if page < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Page number must be greater than 0"
            )
        
        if page_size < 1 or page_size > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Page size must be between 1 and 100"
            )
        
        self.page = page
        self.page_size = page_size