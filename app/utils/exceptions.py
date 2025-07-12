from typing import Optional, Dict, Any
from uuid import UUID


class APIException(Exception):
    """Base exception for API errors"""
    
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self, correlation_id: UUID) -> Dict[str, Any]:
        """Convert exception to error response dictionary"""
        from datetime import datetime
        
        error_dict = {
            "error": {
                "code": self.code,
                "message": self.message,
                "correlation_id": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        if self.details:
            error_dict["error"]["details"] = self.details
        
        return error_dict


class ValidationException(APIException):
    """Raised when request validation fails"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="VALIDATION_ERROR",
            message=message,
            status_code=400,
            details=details
        )


class AuthenticationException(APIException):
    """Raised when authentication fails"""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            code="AUTHENTICATION_ERROR",
            message=message,
            status_code=401
        )


class AuthorizationException(APIException):
    """Raised when authorization fails"""
    
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            code="AUTHORIZATION_ERROR",
            message=message,
            status_code=403
        )


class ResourceNotFoundException(APIException):
    """Raised when requested resource is not found"""
    
    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            code="RESOURCE_NOT_FOUND",
            message=f"{resource_type} with ID {resource_id} not found",
            status_code=404
        )


class ResourceExistsException(APIException):
    """Raised when trying to create a resource that already exists"""
    
    def __init__(self, resource_type: str, identifier: str):
        super().__init__(
            code="RESOURCE_EXISTS",
            message=f"{resource_type} with identifier {identifier} already exists",
            status_code=409
        )


class RateLimitException(APIException):
    """Raised when rate limit is exceeded"""
    
    def __init__(self, retry_after: int):
        super().__init__(
            code="RATE_LIMIT_EXCEEDED",
            message="Rate limit exceeded. Please try again later.",
            status_code=429,
            details={"retry_after": retry_after}
        )


class ServiceUnavailableException(APIException):
    """Raised when a required service is unavailable"""
    
    def __init__(self, service: str, message: Optional[str] = None):
        super().__init__(
            code="SERVICE_UNAVAILABLE",
            message=message or f"{service} service is currently unavailable",
            status_code=503
        )


class InvalidOperationException(APIException):
    """Raised when an invalid operation is attempted"""
    
    def __init__(self, message: str):
        super().__init__(
            code="INVALID_OPERATION",
            message=message,
            status_code=400
        )