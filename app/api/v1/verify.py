from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime, timezone

from app.database import get_db
from app.models.schemas import VerifyRequest, VerifyResponse, ErrorResponse
from app.services.signing_service import SigningService
from app.api.dependencies import (
    get_correlation_id, get_request_info, rate_limiter, validate_content_length
)

router = APIRouter()


@router.post("/verify", response_model=VerifyResponse)
async def verify_signature(
    request: Request,
    verify_request: VerifyRequest,
    db: Session = Depends(get_db),
    correlation_id: UUID = Depends(get_correlation_id),
    _: None = Depends(rate_limiter),
    _content_check: None = Depends(validate_content_length)
):
    """
    Verify an Ed25519 signature.
    
    - **data**: Raw data that was signed
    - **signature**: Base64 encoded signature to verify
    - **public_key**: Base64 encoded public key to verify against
    
    Returns verification result.
    """
    try:
        request_info = await get_request_info(request)
        signing_service = SigningService(db)
        
        is_valid = await signing_service.verify_signature(
            data=verify_request.data,
            signature_b64=verify_request.signature,
            public_key_b64=verify_request.public_key,
            correlation_id=correlation_id
        )
        
        return VerifyResponse(
            is_valid=is_valid,
            timestamp=datetime.now(timezone.utc),
            correlation_id=correlation_id
        )
        
    except Exception as e:
        error_response = ErrorResponse.create(
            code="VERIFICATION_FAILED",
            message=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_response
        )