import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict, Optional
import structlog
from pythonjsonlogger import jsonlogger

from app.config import settings


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records"""
    
    def filter(self, record):
        # Get correlation ID from context if available
        correlation_id = getattr(record, 'correlation_id', None)
        if correlation_id:
            record.correlation_id = correlation_id
        return True


def setup_logging():
    """Configure structured logging for the application"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.LINENO,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                ]
            ),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer() if settings.LOG_FORMAT == "json" else structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure Python logging
    log_level = getattr(logging, settings.LOG_LEVEL.upper())
    
    # Remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    
    # Configure formatter based on format setting
    if settings.LOG_FORMAT == "json":
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d %(funcName)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d'
        )
    
    handler.setFormatter(formatter)
    handler.addFilter(CorrelationIdFilter())
    
    # Configure root logger
    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)
    
    # Add file handler if configured
    if settings.LOG_FILE_PATH:
        file_handler = logging.FileHandler(settings.LOG_FILE_PATH)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(CorrelationIdFilter())
        root_logger.addHandler(file_handler)
    
    # Set specific loggers
    logging.getLogger("uvicorn").setLevel(log_level)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING if not settings.DEBUG else logging.INFO)
    
    return structlog.get_logger()


class LoggerMixin:
    """Mixin class to add logger to any class"""
    
    @property
    def logger(self):
        if not hasattr(self, '_logger'):
            self._logger = structlog.get_logger(self.__class__.__name__)
        return self._logger


def log_api_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    correlation_id: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    error: Optional[str] = None
) -> None:
    """Log API request with structured data"""
    
    logger = structlog.get_logger("api.request")
    
    log_data = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "correlation_id": correlation_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if user_id:
        log_data["user_id"] = user_id
    if ip_address:
        log_data["ip_address"] = ip_address
    if user_agent:
        log_data["user_agent"] = user_agent
    if error:
        log_data["error"] = error
    
    if status_code >= 500:
        logger.error("API request failed", **log_data)
    elif status_code >= 400:
        logger.warning("API request client error", **log_data)
    else:
        logger.info("API request completed", **log_data)


def log_hsm_operation(
    operation: str,
    success: bool,
    duration_ms: float,
    correlation_id: str,
    key_id: Optional[str] = None,
    error: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Log HSM operation with structured data"""
    
    logger = structlog.get_logger("hsm.operation")
    
    log_data = {
        "operation": operation,
        "success": success,
        "duration_ms": duration_ms,
        "correlation_id": correlation_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if key_id:
        log_data["key_id"] = key_id
    if error:
        log_data["error"] = error
    if details:
        log_data["details"] = details
    
    if success:
        logger.info("HSM operation completed", **log_data)
    else:
        logger.error("HSM operation failed", **log_data)