from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database import get_db, check_database_connection
from app.models.schemas import HealthStatus, HSMStatus
from app.hsm.manager import hsm_manager
from app.config import settings

router = APIRouter()


@router.get("/status", response_model=HealthStatus)
async def get_health_status(db: Session = Depends(get_db)):
    """
    Get overall health status of the API.
    
    Returns health status including database and HSM connectivity.
    """
    checks = {}
    
    # Check database connection
    try:
        checks["database"] = check_database_connection()
    except Exception:
        checks["database"] = False
    
    # Check HSM connection
    try:
        hsm_info = hsm_manager.get_hsm_info()
        checks["hsm"] = hsm_info.get("connected", False)
    except Exception:
        checks["hsm"] = False
    
    # Overall status
    overall_status = "healthy" if all(checks.values()) else "unhealthy"
    
    return HealthStatus(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version=settings.VERSION,
        checks=checks
    )


@router.get("/hsm-status", response_model=HSMStatus)
async def get_hsm_status():
    """
    Get detailed HSM status and information.
    
    Returns HSM connectivity, slot information, and token details.
    """
    try:
        info = hsm_manager.get_hsm_info()
        
        return HSMStatus(
            connected=info.get("connected", False),
            slot_id=info.get("slot_id", settings.HSM_SLOT_ID),
            token_label=info.get("token_label"),
            manufacturer=info.get("manufacturer"),
            model=info.get("model"),
            serial_number=info.get("serial_number"),
            total_slots=info.get("total_slots"),
            available_slots=info.get("available_slots"),
            error=info.get("error")
        )
        
    except Exception as e:
        return HSMStatus(
            connected=False,
            slot_id=settings.HSM_SLOT_ID,
            error=str(e)
        )


@router.get("/readiness")
async def readiness_check():
    """
    Readiness check for container orchestration.
    
    Returns 200 if the service is ready to accept requests.
    """
    # Check critical dependencies
    db_healthy = check_database_connection()
    
    try:
        hsm_info = hsm_manager.get_hsm_info()
        hsm_healthy = hsm_info.get("connected", False)
    except Exception:
        hsm_healthy = False
    
    if db_healthy and hsm_healthy:
        return {"status": "ready"}
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready"
        )


@router.get("/liveness")
async def liveness_check():
    """
    Liveness check for container orchestration.
    
    Returns 200 if the service is alive and responsive.
    """
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}