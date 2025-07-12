from fastapi import APIRouter, Depends, Request, HTTPException, status, Query
from sqlalchemy.orm import Session
from uuid import UUID

from app.database import get_db
from app.models.schemas import (
    SignRequest, SignResponse, BatchSignRequest, BatchSignResponse, 
    SigningHistoryResponse, ErrorResponse
)
from app.services.signing_service import SigningService
from app.services.audit_service import AuditService
from app.api.dependencies import (
    get_correlation_id, get_request_info, rate_limiter, 
    validate_content_length, check_hsm_availability
)

router = APIRouter()


@router.post("/{key_id}/sign", response_model=SignResponse)
async def sign_data(
    key_id: UUID,
    request: Request,
    sign_request: SignRequest,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter),
    _content_check: None = Depends(validate_content_length),
    _hsm_check: None = Depends(check_hsm_availability)
):
    """
    Sign data with the specified key.
    
    - **key_id**: UUID of the key to use for signing
    - **data**: Raw data to sign (max 1MB)
    
    Returns the signature and metadata.
    """
    try:
        request_info = await get_request_info(request)
        signing_service = SigningService(db)
        
        result = await signing_service.sign_data(
            key_id=key_id,
            request=sign_request,
            user_id="anonymous",  # Authentication disabled
            correlation_id=correlation_id,
            ip_address=request_info["ip_address"],
            user_agent=request_info["user_agent"]
        )
        
        return result
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="SIGNING_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        
        status_code = status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_500_INTERNAL_SERVER_ERROR
        if "not active" in str(e).lower() or "expired" in str(e).lower():
            status_code = status.HTTP_400_BAD_REQUEST
        
        raise HTTPException(
            status_code=status_code,
            detail=error_response
        )


@router.post("/batch-sign", response_model=BatchSignResponse)
async def batch_sign_data(
    request: Request,
    batch_request: BatchSignRequest,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter),
    _content_check: None = Depends(validate_content_length),
    _hsm_check: None = Depends(check_hsm_availability)
):
    """
    Sign multiple data items with the same key.
    
    - **key_id**: UUID of the key to use for signing
    - **data_items**: List of raw data items to sign (max 100 items, 5MB total)
    
    Returns signatures for all data items.
    """
    try:
        request_info = await get_request_info(request)
        signing_service = SigningService(db)
        
        result = await signing_service.batch_sign(
            request=batch_request,
            user_id="anonymous",  # Authentication disabled
            correlation_id=correlation_id,
            ip_address=request_info["ip_address"],
            user_agent=request_info["user_agent"]
        )
        
        return result
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="BATCH_SIGNING_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        
        status_code = status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_500_INTERNAL_SERVER_ERROR
        if "not active" in str(e).lower() or "expired" in str(e).lower():
            status_code = status.HTTP_400_BAD_REQUEST
        
        raise HTTPException(
            status_code=status_code,
            detail=error_response
        )


@router.get("/{key_id}/sign-history", response_model=SigningHistoryResponse)
async def get_signing_history(
    key_id: UUID,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    _: None = Depends(rate_limiter)
):
    """
    Get signing history for a specific key.
    
    - **key_id**: UUID of the key
    - **page**: Page number (1-based)
    - **page_size**: Items per page (1-100)
    
    Returns paginated signing history with audit information.
    """
    try:
        audit_service = AuditService(db)
        result = await audit_service.get_signing_history(
            key_id=key_id,
            page=page,
            page_size=page_size
        )
        
        return SigningHistoryResponse(**result)
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="SIGNING_HISTORY_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )