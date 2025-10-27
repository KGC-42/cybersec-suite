from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any
from ..database import get_db
from ..auth import get_current_user
from ..models.security import SecurityEvent
from ..services.phishing_detector import PhishingDetector

router = APIRouter(prefix="/api/v1/phishing", tags=["phishing"])

class URLCheckRequest(BaseModel):
    url: str

detector = PhishingDetector()

@router.post("/check")
async def check_url(
    request: URLCheckRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    try:
        result = detector.check_url(request.url)
        
        severity = "high" if result.get("is_phishing", False) else "low"
        
        security_event = SecurityEvent(
            source="phishing",
            event_type="url_check",
            severity=severity,
            details={
                "url": request.url,
                "result": result,
                "user_id": current_user.id
            },
            timestamp=datetime.utcnow()
        )
        
        db.add(security_event)
        db.commit()
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))