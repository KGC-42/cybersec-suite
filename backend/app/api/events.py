from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import get_db
from auth import get_current_user
from models.security import SecurityEvent

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
    event = SecurityEvent(
        agent_id=data.agent_id,
        organization_id=current_user.get("organization_id", 1),
        source=data.source,
        severity=data.severity,
        title=data.title,
        description=data.description,
        details=data.details
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"id": event.id, "status": "created"}


@router.get("/")
async def list_events(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    organization_id = current_user.get("organization_id", 1)
    events = db.query(SecurityEvent)\
        .filter(SecurityEvent.organization_id == organization_id)\
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