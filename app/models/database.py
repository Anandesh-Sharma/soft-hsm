from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Enum, Text, JSON
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
import uuid

from app.database import Base


class KeyStatus(enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"
    pending = "pending"


class OperationStatus(enum.Enum):
    success = "success"
    failure = "failure"
    pending = "pending"


class KeyMetadata(Base):
    __tablename__ = "key_metadata"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hsm_key_id = Column(String(255), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(Enum(KeyStatus, name='key_status'), nullable=False, default=KeyStatus.active, index=True)
    purpose = Column(String(100))
    created_by = Column(String(255), index=True)
    last_used_at = Column(DateTime(timezone=True))
    usage_count = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True))
    key_metadata = Column("metadata", JSON, default={})
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="key", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<KeyMetadata(id={self.id}, hsm_key_id={self.hsm_key_id}, status={self.status})>"


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    correlation_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    operation = Column(String(100), nullable=False)
    key_id = Column(UUID(as_uuid=True), ForeignKey("key_metadata.id", ondelete="CASCADE"), index=True)
    user_id = Column(String(255), index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    ip_address = Column(INET)
    user_agent = Column(Text)
    status = Column(Enum(OperationStatus, name='operation_status'), nullable=False)
    details = Column(JSON, default={})
    error_message = Column(Text)
    
    # Relationships
    key = relationship("KeyMetadata", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, operation={self.operation}, status={self.status})>"


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    api_key = Column(String(255), unique=True, index=True)
    api_key_created_at = Column(DateTime(timezone=True))
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name = Column(String(255), nullable=False)
    permissions = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self):
        return f"<APIKey(id={self.id}, name={self.name}, user_id={self.user_id})>"