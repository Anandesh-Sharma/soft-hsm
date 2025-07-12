from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from uuid import UUID
import logging

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.database import AuditLog, OperationStatus
from app.models.schemas import AuditLogResponse

logger = logging.getLogger(__name__)


class AuditService:
    """Service for audit logging operations"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def log_operation(
        self,
        operation: str,
        correlation_id: UUID,
        success: bool,
        user_id: Optional[str] = None,
        key_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """
        Log an operation to the audit log.
        
        Args:
            operation: Operation name
            correlation_id: Request correlation ID
            success: Whether operation was successful
            user_id: User performing the operation
            key_id: Key involved in the operation
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional operation details
            error_message: Error message if operation failed
        """
        try:
            audit_log = AuditLog(
                correlation_id=correlation_id,
                operation=operation,
                key_id=key_id,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                status=OperationStatus.success if success else OperationStatus.failure,
                details=details or {},
                error_message=error_message
            )
            
            self.db.add(audit_log)
            self.db.commit()
            
            logger.info(
                f"Audit log created: operation={operation}, "
                f"status={'success' if success else 'failure'}, "
                f"correlation_id={correlation_id}"
            )
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            # Don't raise - audit logging should not break the main flow
    
    async def get_signing_history(
        self,
        key_id: UUID,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """
        Get signing history for a specific key.
        
        Args:
            key_id: Key UUID
            page: Page number (1-based)
            page_size: Items per page
            
        Returns:
            Dictionary with audit logs and pagination info
        """
        # Query for signing operations
        query = self.db.query(AuditLog).filter(
            AuditLog.key_id == key_id,
            AuditLog.operation.in_(["sign_data", "batch_sign"])
        ).order_by(desc(AuditLog.timestamp))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * page_size
        logs = query.offset(offset).limit(page_size).all()
        
        # Convert to response models
        log_responses = [
            AuditLogResponse(
                id=log.id,
                correlation_id=log.correlation_id,
                operation=log.operation,
                key_id=log.key_id,
                user_id=log.user_id,
                timestamp=log.timestamp,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                status=log.status,
                details=log.details,
                error_message=log.error_message
            )
            for log in logs
        ]
        
        return {
            "logs": log_responses,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    async def get_user_activity(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """
        Get activity logs for a specific user.
        
        Args:
            user_id: User ID
            start_date: Start date filter
            end_date: End date filter
            page: Page number (1-based)
            page_size: Items per page
            
        Returns:
            Dictionary with audit logs and pagination info
        """
        query = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id
        ).order_by(desc(AuditLog.timestamp))
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * page_size
        logs = query.offset(offset).limit(page_size).all()
        
        # Convert to response models
        log_responses = [
            AuditLogResponse(
                id=log.id,
                correlation_id=log.correlation_id,
                operation=log.operation,
                key_id=log.key_id,
                user_id=log.user_id,
                timestamp=log.timestamp,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                status=log.status,
                details=log.details,
                error_message=log.error_message
            )
            for log in logs
        ]
        
        return {
            "logs": log_responses,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    async def get_failed_operations(
        self,
        operation: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditLogResponse]:
        """
        Get recent failed operations.
        
        Args:
            operation: Filter by operation type
            limit: Maximum number of records to return
            
        Returns:
            List of failed audit logs
        """
        query = self.db.query(AuditLog).filter(
            AuditLog.status == OperationStatus.failure
        ).order_by(desc(AuditLog.timestamp))
        
        if operation:
            query = query.filter(AuditLog.operation == operation)
        
        logs = query.limit(limit).all()
        
        return [
            AuditLogResponse(
                id=log.id,
                correlation_id=log.correlation_id,
                operation=log.operation,
                key_id=log.key_id,
                user_id=log.user_id,
                timestamp=log.timestamp,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                status=log.status,
                details=log.details,
                error_message=log.error_message
            )
            for log in logs
        ]
    
    async def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """
        Clean up old audit logs.
        
        Args:
            days_to_keep: Number of days to keep logs
            
        Returns:
            Number of deleted records
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
        
        deleted_count = self.db.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        ).delete()
        
        self.db.commit()
        
        logger.info(f"Cleaned up {deleted_count} old audit logs")
        return deleted_count