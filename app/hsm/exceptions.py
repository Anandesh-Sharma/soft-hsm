class HSMException(Exception):
    """Base exception for HSM operations"""
    def __init__(self, message: str, code: str = "HSM_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class HSMConnectionError(HSMException):
    """Raised when HSM connection fails"""
    def __init__(self, message: str = "Failed to connect to HSM"):
        super().__init__(message, "HSM_CONNECTION_ERROR")


class HSMAuthenticationError(HSMException):
    """Raised when HSM authentication fails"""
    def __init__(self, message: str = "HSM authentication failed"):
        super().__init__(message, "HSM_AUTH_ERROR")


class HSMKeyNotFoundError(HSMException):
    """Raised when requested key is not found in HSM"""
    def __init__(self, key_id: str):
        message = f"Key {key_id} not found in HSM"
        super().__init__(message, "HSM_KEY_NOT_FOUND")


class HSMOperationError(HSMException):
    """Raised when HSM operation fails"""
    def __init__(self, operation: str, message: str):
        full_message = f"HSM operation '{operation}' failed: {message}"
        super().__init__(full_message, "HSM_OPERATION_ERROR")


class HSMSlotError(HSMException):
    """Raised when HSM slot is not available"""
    def __init__(self, slot_id: int):
        message = f"HSM slot {slot_id} is not available"
        super().__init__(message, "HSM_SLOT_ERROR")


class HSMSessionError(HSMException):
    """Raised when HSM session management fails"""
    def __init__(self, message: str = "HSM session error"):
        super().__init__(message, "HSM_SESSION_ERROR")