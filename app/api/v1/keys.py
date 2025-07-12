from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException, status, Query
from sqlalchemy.orm import Session
from uuid import UUID

from app.database import get_db
from app.models.schemas import (
    KeyGenerateRequest, KeyResponse, KeyListResponse, ErrorResponse
)
from app.models.database import KeyStatus
from app.services.key_service import KeyService
from app.api.dependencies import (
    get_correlation_id, get_request_info, rate_limiter, 
    validate_content_length, check_hsm_availability, PaginationParams
)

router = APIRouter()


@router.post("/generate", response_model=KeyResponse, status_code=status.HTTP_201_CREATED)
async def generate_key(
    request: Request,
    key_request: KeyGenerateRequest,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter),
    _content_check: None = Depends(validate_content_length),
    _hsm_check: None = Depends(check_hsm_availability)
):
    """
    Generate a new Ed25519 key pair in HSM.
    
    - **purpose**: Optional purpose description for the key
    - **expires_in_days**: Optional expiration time in days (1-3650)
    - **metadata**: Optional additional metadata
    
    Returns the generated key information including public key.
    """
    try:
        request_info = await get_request_info(request)
        key_service = KeyService(db)
        
        result = await key_service.generate_key(
            request=key_request,
            user_id="anonymous",  # Authentication disabled
            correlation_id=correlation_id,
            ip_address=request_info["ip_address"],
            user_agent=request_info["user_agent"]
        )
        
        return result
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="KEY_GENERATION_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )


@router.get("/{key_id}", response_model=KeyResponse)
async def get_key(
    key_id: UUID,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter)
):
    """
    Retrieve key information by ID.
    
    Returns the key metadata including public key and usage statistics.
    """
    try:
        key_service = KeyService(db)
        result = await key_service.get_key(key_id)
        
        return result
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="KEY_RETRIEVAL_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_key(
    key_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter),
    _hsm_check: None = Depends(check_hsm_availability)
):
    """
    Securely delete a key from HSM.
    
    This operation revokes the key and removes it from the HSM.
    The key metadata is retained for audit purposes but marked as revoked.
    """
    try:
        request_info = await get_request_info(request)
        key_service = KeyService(db)
        
        await key_service.delete_key(
            key_id=key_id,
            user_id="anonymous",  # Authentication disabled
            correlation_id=correlation_id,
            ip_address=request_info["ip_address"],
            user_agent=request_info["user_agent"]
        )
        
        return
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="KEY_DELETION_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )


@router.get("/", response_model=KeyListResponse)
async def list_keys(
    request: Request,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    status_filter: Optional[KeyStatus] = Query(None, description="Filter by key status"),
    user_filter: Optional[str] = Query(None, description="Filter by creator user ID (admin only)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    _: None = Depends(rate_limiter)
):
    """
    List keys with pagination and filtering.
    
    - **status**: Filter by key status (active, revoked, expired, pending)
    - **user**: Filter by creator user ID (admin only)
    - **page**: Page number (1-based)
    - **page_size**: Items per page (1-100)
    
    Returns paginated list of keys.
    """
    try:
        # Authentication disabled - show all keys if no filter provided
        # In production, you would implement proper access control
        
        key_service = KeyService(db)
        result = await key_service.list_keys(
            user_id=user_filter,
            status=status_filter,
            page=page,
            page_size=page_size
        )
        
        return KeyListResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        error_response = ErrorResponse.create(
            code="KEY_LIST_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )