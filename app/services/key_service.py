from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID
import logging

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.database import KeyMetadata, KeyStatus
from app.models.schemas import KeyGenerateRequest, KeyResponse
from app.hsm.manager import hsm_manager
from app.utils.exceptions import ResourceNotFoundException, InvalidOperationException
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class KeyService:
    """Service for key management operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)
    
    async def generate_key(
        self,
        request: KeyGenerateRequest,
        user_id: str,
        correlation_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> KeyResponse:
        """
        Generate new Ed25519 key pair in HSM.
        
        Args:
            request: Key generation request
            user_id: ID of user generating the key
            correlation_id: Request correlation ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Generated key information
        """
        try:
            # Generate key pair in HSM
            hsm_key_id, public_key = hsm_manager.generate_key_pair()
            
            # Calculate expiration if specified
            expires_at = None
            if request.expires_in_days:
                expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)
            
            # Create database record
            key_metadata = KeyMetadata(
                hsm_key_id=hsm_key_id,
                public_key=public_key,
                status=KeyStatus.active,
                purpose=request.purpose,
                created_by=user_id,
                expires_at=expires_at,
                key_metadata=request.metadata
            )
            
            self.db.add(key_metadata)
            self.db.commit()
            self.db.refresh(key_metadata)
            
            # Log audit event
            await self.audit_service.log_operation(
                operation="key_generate",
                key_id=key_metadata.id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                details={
                    "purpose": request.purpose,
                    "expires_in_days": request.expires_in_days
                }
            )
            
            logger.info(f"Generated key {key_metadata.id} for user {user_id}")
            
            return KeyResponse(
                id=key_metadata.id,
                public_key=key_metadata.public_key,
                status=key_metadata.status,
                purpose=key_metadata.purpose,
                created_at=key_metadata.created_at,
                expires_at=key_metadata.expires_at,
                usage_count=key_metadata.usage_count,
                metadata=key_metadata.key_metadata
            )
            
        except Exception as e:
            # Log audit event for failure
            await self.audit_service.log_operation(
                operation="key_generate",
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"Failed to generate key: {str(e)}")
            raise
    
    async def get_key(self, key_id: UUID) -> KeyResponse:
        """
        Get key information by ID.
        
        Args:
            key_id: Key UUID
            
        Returns:
            Key information
            
        Raises:
            ResourceNotFoundException: If key not found
        """
        key_metadata = self.db.query(KeyMetadata).filter(
            KeyMetadata.id == key_id
        ).first()
        
        if not key_metadata:
            raise ResourceNotFoundException("Key", str(key_id))
        
        # Check if key is expired
        if key_metadata.expires_at and key_metadata.expires_at < datetime.now(timezone.utc):
            key_metadata.status = KeyStatus.expired
            self.db.commit()
        
        return KeyResponse(
            id=key_metadata.id,
            public_key=key_metadata.public_key,
            status=key_metadata.status,
            purpose=key_metadata.purpose,
            created_at=key_metadata.created_at,
            expires_at=key_metadata.expires_at,
            usage_count=key_metadata.usage_count,
            metadata=key_metadata.key_metadata
        )
    
    async def delete_key(
        self,
        key_id: UUID,
        user_id: str,
        correlation_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> bool:
        """
        Delete key from HSM and database.
        
        Args:
            key_id: Key UUID
            user_id: ID of user deleting the key
            correlation_id: Request correlation ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            True if successful
            
        Raises:
            ResourceNotFoundException: If key not found
            InvalidOperationException: If key cannot be deleted
        """
        try:
            # Get key from database
            key_metadata = self.db.query(KeyMetadata).filter(
                KeyMetadata.id == key_id
            ).first()
            
            if not key_metadata:
                raise ResourceNotFoundException("Key", str(key_id))
            
            # Check if key is already revoked
            if key_metadata.status == KeyStatus.revoked:
                raise InvalidOperationException("Key is already revoked")
            
            # Delete from HSM
            hsm_manager.delete_key_pair(key_metadata.hsm_key_id)
            
            # Update status in database (soft delete)
            key_metadata.status = KeyStatus.revoked
            self.db.commit()
            
            # Log audit event
            await self.audit_service.log_operation(
                operation="key_delete",
                key_id=key_metadata.id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            logger.info(f"Deleted key {key_id} by user {user_id}")
            return True
            
        except Exception as e:
            # Log audit event for failure
            await self.audit_service.log_operation(
                operation="key_delete",
                key_id=key_id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"Failed to delete key {key_id}: {str(e)}")
            raise
    
    async def list_keys(
        self,
        user_id: Optional[str] = None,
        status: Optional[KeyStatus] = None,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """
        List keys with pagination and filtering.
        
        Args:
            user_id: Filter by creator user ID
            status: Filter by key status
            page: Page number (1-based)
            page_size: Items per page
            
        Returns:
            Dictionary with keys and pagination info
        """
        # Build query
        query = self.db.query(KeyMetadata)
        
        if user_id:
            query = query.filter(KeyMetadata.created_by == user_id)
        
        if status:
            query = query.filter(KeyMetadata.status == status)
        
        # Check for expired keys and update status
        now = datetime.now(timezone.utc)
        expired_keys = query.filter(
            and_(
                KeyMetadata.expires_at != None,
                KeyMetadata.expires_at < now,
                KeyMetadata.status == KeyStatus.active
            )
        ).all()
        
        for key in expired_keys:
            key.status = KeyStatus.expired
        
        if expired_keys:
            self.db.commit()
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * page_size
        keys = query.offset(offset).limit(page_size).all()
        
        # Convert to response models
        key_responses = [
            KeyResponse(
                id=key.id,
                public_key=key.public_key,
                status=key.status,
                purpose=key.purpose,
                created_at=key.created_at,
                expires_at=key.expires_at,
                usage_count=key.usage_count,
                metadata=key.key_metadata
            )
            for key in keys
        ]
        
        return {
            "keys": key_responses,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    async def update_key_usage(self, key_id: UUID) -> None:
        """
        Update key usage statistics.
        
        Args:
            key_id: Key UUID
        """
        key_metadata = self.db.query(KeyMetadata).filter(
            KeyMetadata.id == key_id
        ).first()
        
        if key_metadata:
            key_metadata.usage_count += 1
            key_metadata.last_used_at = datetime.now(timezone.utc)
            self.db.commit()