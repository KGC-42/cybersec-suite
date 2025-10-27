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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        breaches = await monitor.check_email(request.email)
        
        severity = "high" if breaches else "low"
        
        security_event = SecurityEvent(
            source="darkweb",
            severity=severity,
            event_type="breach_check",
            description=f"Email breach check for {request.email}",
            user_id=current_user.get("id"),
            timestamp=datetime.utcnow(),
            metadata={"email": request.email, "breach_count": len(breaches)}
        )
        
        db.add(security_event)
        db.commit()
        
        return {"breaches": breaches}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))