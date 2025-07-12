from pydantic import BaseModel, Field, EmailStr, validator, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime
from uuid import UUID
import re

from app.models.database import KeyStatus, OperationStatus


# Base schemas
class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# Key Management Schemas
class KeyGenerateRequest(BaseSchema):
    purpose: Optional[str] = Field(None, max_length=100, description="Purpose of the key")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650, description="Key expiration in days")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('purpose')
    def validate_purpose(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
            raise ValueError('Purpose must contain only alphanumeric characters, spaces, hyphens and underscores')
        return v


class KeyResponse(BaseSchema):
    id: UUID
    public_key: str
    status: KeyStatus
    purpose: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    usage_count: int
    metadata: Dict[str, Any]


class KeyListResponse(BaseSchema):
    keys: List[KeyResponse]
    total: int
    page: int
    page_size: int


# Signing Schemas
class SignRequest(BaseSchema):
    data: str = Field(..., description="Raw data to sign")
    
    @validator('data')
    def validate_data_size(cls, v):
        # Check if data is not too large (1MB limit)
        if len(v.encode('utf-8')) > 1_048_576:
            raise ValueError('Data size exceeds 1MB limit')
        return v


class SignResponse(BaseSchema):
    signature: str = Field(..., description="Base64 encoded signature")
    key_id: UUID
    timestamp: datetime
    correlation_id: UUID


class BatchSignRequest(BaseSchema):
    key_id: UUID
    data_items: List[str] = Field(..., max_items=100, description="List of raw data to sign")
    
    @validator('data_items')
    def validate_batch_size(cls, v):
        total_size = sum(len(item.encode('utf-8')) for item in v)
        if total_size > 5_242_880:  # 5MB total limit for batch
            raise ValueError('Total batch data size exceeds 5MB limit')
        return v


class BatchSignResponse(BaseSchema):
    signatures: List[str]
    key_id: UUID
    timestamp: datetime
    correlation_id: UUID
    signed_count: int


# Verification Schemas
class VerifyRequest(BaseSchema):
    data: str = Field(..., description="Raw data that was signed")
    signature: str = Field(..., description="Base64 encoded signature to verify")
    public_key: str = Field(..., description="Base64 encoded public key to verify against")


class VerifyResponse(BaseSchema):
    is_valid: bool
    timestamp: datetime
    correlation_id: UUID


# Authentication Schemas
class UserCreate(BaseSchema):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must contain only alphanumeric characters and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserResponse(BaseSchema):
    id: UUID
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime]


class TokenRequest(BaseSchema):
    username: str
    password: str


class TokenResponse(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class APIKeyCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=100)
    permissions: Optional[Dict[str, Any]] = Field(default_factory=dict)
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseSchema):
    id: UUID
    name: str
    api_key: str  # Only returned on creation
    permissions: Dict[str, Any]
    created_at: datetime
    expires_at: Optional[datetime]


# Audit Log Schemas
class AuditLogResponse(BaseSchema):
    id: UUID
    correlation_id: UUID
    operation: str
    key_id: Optional[UUID]
    user_id: Optional[str]
    timestamp: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    status: OperationStatus
    details: Dict[str, Any]
    error_message: Optional[str]


class SigningHistoryResponse(BaseSchema):
    logs: List[AuditLogResponse]
    total: int
    page: int
    page_size: int


# Health Check Schemas
class HealthStatus(BaseSchema):
    status: str
    timestamp: datetime
    version: str
    checks: Dict[str, bool]


class HSMStatus(BaseSchema):
    connected: bool
    slot_id: int
    token_label: Optional[str]
    manufacturer: Optional[str]
    model: Optional[str]
    serial_number: Optional[str]
    total_slots: Optional[int]
    available_slots: Optional[int]
    error: Optional[str]


# Error Response Schema
class ErrorResponse(BaseSchema):
    error: Dict[str, Any] = Field(..., description="Error details")
    
    @staticmethod
    def create(code: str, message: str, correlation_id: UUID) -> Dict[str, Any]:
        return {
            "error": {
                "code": code,
                "message": message,
                "correlation_id": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }