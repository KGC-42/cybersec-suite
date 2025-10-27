from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.database import get_db
from app.auth import get_current_user
from app.services.clamav_scanner import ClamAVScanner
from app.models.security import SecurityEvent, Agent

router = APIRouter(prefix="/api/v1/scanner", tags=["scanner"])


@router.get("/status")
async def scanner_status():
    return {"clamav": "ready"}


@router.post("/test-eicar")
async def test_eicar_scan(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test ClamAV with EICAR test file"""
    scanner = ClamAVScanner()
    result = scanner.test_eicar()

    if result.get("infected"):
        agent = db.query(Agent).first()

        if agent:
            event = SecurityEvent(
                agent_id=agent.id,
                organization_id=1,  # Default org
                source="clamav",
                severity="high",
                title=f"Test: {result['virus_name']} detected",
                description="EICAR test successfully detected",
                details=result
            )
            db.add(event)
            db.commit()

    return result