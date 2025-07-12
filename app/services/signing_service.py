import base64
from typing import List, Optional
from datetime import datetime, timezone
from uuid import UUID
import logging

from sqlalchemy.orm import Session

from app.models.database import KeyMetadata, KeyStatus
from app.models.schemas import SignRequest, SignResponse, BatchSignRequest, BatchSignResponse
from app.hsm.manager import hsm_manager
from app.hsm.crypto import EdwardsCurveOperations
from app.utils.exceptions import ResourceNotFoundException, InvalidOperationException
from app.services.audit_service import AuditService
from app.services.key_service import KeyService

logger = logging.getLogger(__name__)


class SigningService:
    """Service for signing operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)
        self.key_service = KeyService(db)
        self.crypto_ops = EdwardsCurveOperations()
    
    async def sign_data(
        self,
        key_id: UUID,
        request: SignRequest,
        user_id: str,
        correlation_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> SignResponse:
        """
        Sign data with specified key.
        
        Args:
            key_id: Key UUID
            request: Signing request
            user_id: ID of user performing signing
            correlation_id: Request correlation ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Signature response
        """
        try:
            # Get key from database
            key_metadata = self.db.query(KeyMetadata).filter(
                KeyMetadata.id == key_id
            ).first()
            
            if not key_metadata:
                raise ResourceNotFoundException("Key", str(key_id))
            
            # Check key status
            if key_metadata.status != KeyStatus.active:
                raise InvalidOperationException(f"Key is not active (status: {key_metadata.status.value})")
            
            # Check if key is expired
            if key_metadata.expires_at and key_metadata.expires_at < datetime.now(timezone.utc):
                key_metadata.status = KeyStatus.expired
                self.db.commit()
                raise InvalidOperationException("Key has expired")
            
            # Convert string data to bytes
            data = request.data.encode('utf-8')
            
            # Sign data using HSM
            signature_bytes = hsm_manager.sign_data(key_metadata.hsm_key_id, data)
            
            # Encode signature to base64
            signature = self.crypto_ops.encode_signature(signature_bytes)
            
            # Update key usage
            await self.key_service.update_key_usage(key_id)
            
            # Log audit event
            await self.audit_service.log_operation(
                operation="sign_data",
                key_id=key_id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                details={
                    "data_size": len(data)
                }
            )
            
            logger.info(f"Signed data with key {key_id} for user {user_id}")
            
            return SignResponse(
                signature=signature,
                key_id=key_id,
                timestamp=datetime.now(timezone.utc),
                correlation_id=correlation_id
            )
            
        except Exception as e:
            # Log audit event for failure
            await self.audit_service.log_operation(
                operation="sign_data",
                key_id=key_id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"Failed to sign data with key {key_id}: {str(e)}")
            raise
    
    async def batch_sign(
        self,
        request: BatchSignRequest,
        user_id: str,
        correlation_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> BatchSignResponse:
        """
        Sign multiple data items with the same key.
        
        Args:
            request: Batch signing request
            user_id: ID of user performing signing
            correlation_id: Request correlation ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Batch signature response
        """
        try:
            # Get key from database
            key_metadata = self.db.query(KeyMetadata).filter(
                KeyMetadata.id == request.key_id
            ).first()
            
            if not key_metadata:
                raise ResourceNotFoundException("Key", str(request.key_id))
            
            # Check key status
            if key_metadata.status != KeyStatus.active:
                raise InvalidOperationException(f"Key is not active (status: {key_metadata.status.value})")
            
            # Check if key is expired
            if key_metadata.expires_at and key_metadata.expires_at < datetime.now(timezone.utc):
                key_metadata.status = KeyStatus.expired
                self.db.commit()
                raise InvalidOperationException("Key has expired")
            
            signatures = []
            total_data_size = 0
            
            # Sign each data item
            for data_str in request.data_items:
                try:
                    data = data_str.encode('utf-8')
                    total_data_size += len(data)
                    
                    # Sign data using HSM
                    signature_bytes = hsm_manager.sign_data(key_metadata.hsm_key_id, data)
                    
                    # Encode signature to base64
                    signature = self.crypto_ops.encode_signature(signature_bytes)
                    signatures.append(signature)
                    
                except Exception as e:
                    logger.error(f"Failed to sign item in batch: {str(e)}")
                    raise InvalidOperationException(f"Failed to sign data item: {str(e)}")
            
            # Update key usage
            key_metadata.usage_count += len(signatures)
            key_metadata.last_used_at = datetime.now(timezone.utc)
            self.db.commit()
            
            # Log audit event
            await self.audit_service.log_operation(
                operation="batch_sign",
                key_id=request.key_id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                details={
                    "item_count": len(signatures),
                    "total_data_size": total_data_size
                }
            )
            
            logger.info(f"Batch signed {len(signatures)} items with key {request.key_id} for user {user_id}")
            
            return BatchSignResponse(
                signatures=signatures,
                key_id=request.key_id,
                timestamp=datetime.now(timezone.utc),
                correlation_id=correlation_id,
                signed_count=len(signatures)
            )
            
        except Exception as e:
            # Log audit event for failure
            await self.audit_service.log_operation(
                operation="batch_sign",
                key_id=request.key_id,
                user_id=user_id,
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"Failed batch signing with key {request.key_id}: {str(e)}")
            raise
    
    async def verify_signature(
        self,
        data: str,
        signature_b64: str,
        public_key_b64: str,
        correlation_id: UUID
    ) -> bool:
        """
        Verify Ed25519 signature.
        
        Args:
            data: Raw data that was signed
            signature_b64: Base64 encoded signature
            public_key_b64: Base64 encoded public key
            correlation_id: Request correlation ID
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Convert string data to bytes, decode signature and public key from base64
            data_bytes = data.encode('utf-8')
            signature = base64.b64decode(signature_b64, validate=True)
            public_key = base64.b64decode(public_key_b64, validate=True)
            
            # Verify signature
            is_valid = self.crypto_ops.verify_signature(public_key, data_bytes, signature)
            
            logger.info(f"Signature verification result: {is_valid} (correlation_id: {correlation_id})")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False