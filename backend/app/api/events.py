from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.database import get_db
from app.auth import get_current_user
from app.models.security import SecurityEvent
from app.services.report_generator import ReportGenerator
from app.services.email_service import email_service

router = APIRouter(prefix="/api/v1/events", tags=["events"])

class EventCreate(BaseModel):
    agent_id: int
    source: str
    severity: str
    title: str
    description: Optional[str] = None
    details: Optional[dict] = None

@router.post("/ingest")
async def ingest_event(
    data: EventCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from app.models.security import Agent, User
    
    event = SecurityEvent(
        agent_id=data.agent_id,
        organization_id=1,
        source=data.source,
        severity=data.severity,
        title=data.title,
        description=data.description,
        details=data.details
    )
    db.add(event)
    db.commit()
    
    # Auto-send email for critical/high severity alerts
    if data.severity in ["critical", "high"]:
        try:
            # Get agent's user email
            agent = db.query(Agent).filter(Agent.id == data.agent_id).first()
            if agent and agent.user_id:
                user = db.query(User).filter(User.id == agent.user_id).first()
                if user and user.email_notifications_enabled:
                    notification_email = user.notification_email or user.email
                    
                    await email_service.send_alert_email(
                        to_email=notification_email,
                        subject=data.title,
                        alert_type=data.source,
                        severity=data.severity,
                        description=data.description or "Security threat detected",
                        details=data.details or {}
                    )
        except Exception as e:
            print(f"Failed to send email notification: {e}")
    
    return {"id": event.id, "status": "created"}

@router.get("/")
async def list_events(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    events = db.query(SecurityEvent)\
        .order_by(SecurityEvent.timestamp.desc())\
        .limit(50)\
        .all()
    return [
        {
            "id": e.id,
            "agent_id": e.agent_id,
            "source": e.source,
            "severity": e.severity,
            "title": e.title,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "acknowledged": e.acknowledged
        }
        for e in events
    ]

@router.get("/report/weekly")
async def get_weekly_report(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate weekly security report"""
    try:
        generator = ReportGenerator(db)
        report = generator.generate_weekly_report()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@router.post("/test-email")
async def test_email_notification(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test email notification system"""
    try:
        result = await email_service.send_alert_email(
            to_email="kgc78423@gmail.com",
            subject="Test Alert",
            alert_type="Malware Detection",
            severity="high",
            description="This is a test email from GuardianOS",
            details={
                "File": "test.exe",
                "Threat": "Trojan.Generic",
                "Action": "Quarantined"
            }
        )
        return {"message": "Test email sent!", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/user/settings")
async def get_user_settings(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user notification settings"""
    from app.models.security import User
    
    user_id = int(current_user.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "email": user.email,
        "notification_email": user.notification_email or user.email,
        "email_notifications_enabled": user.email_notifications_enabled
    }

@router.put("/user/settings")
async def update_user_settings(
    notification_email: str = None,
    email_notifications_enabled: bool = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user notification settings"""
    from app.models.security import User
    
    user_id = int(current_user.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if notification_email is not None:
        user.notification_email = notification_email
    if email_notifications_enabled is not None:
        user.email_notifications_enabled = email_notifications_enabled
    
    db.commit()
    
    return {"message": "Settings updated successfully"}