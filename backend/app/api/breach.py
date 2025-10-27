from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any, List
from ..database import get_db
from ..auth import get_current_user
from ..models.security import SecurityEvent
from ..services.breach_monitor import BreachMonitor

router = APIRouter(prefix="/api/v1/breach", tags=["breach"])

class EmailCheckRequest(BaseModel):
    email: str

monitor = BreachMonitor()

@router.post("/check")
async def check_email_breaches(
    request: EmailCheckRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    try:
        breaches = monitor.check_email(request.email)
        
        # Log security event
        severity = "high" if breaches else "low"
        event = SecurityEvent(
            user_id=current_user.id,
            event_type="breach_check",
            source="darkweb",
            severity=severity,
            description=f"Breach check performed for email: {request.email}",
            metadata={
                "email": request.email,
                "breaches_found": len(breaches) if breaches else 0,
                "timestamp": datetime.utcnow().isoformat()
            },
            timestamp=datetime.utcnow()
        )
        db.add(event)
        db.commit()
        
        return {"breaches": breaches}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking breaches: {str(e)}")