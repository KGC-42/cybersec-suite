from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any
from app.database import get_db
from app.auth import get_current_user
from app.models.security import Agent

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

class AgentRegister(BaseModel):
    hostname: str
    platform: str
    arch: str
    agent_version: str

@router.post("/register")
async def register_agent(
    data: AgentRegister,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    agent = Agent(
        organization_id=1,
        hostname=data.hostname,
        platform=data.platform,
        arch=data.arch,
        agent_version=data.agent_version
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return {"id": agent.id, "hostname": agent.hostname}

@router.get("/")
async def list_agents(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    agents = db.query(Agent).all()
    return [
        {
            "id": a.id,
            "hostname": a.hostname,
            "platform": a.platform,
            "arch": a.arch,  # ✅ ADDED
            "agent_version": a.agent_version,  # ✅ ADDED
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,  # ✅ ADDED
            "status": "online"
        }
        for a in agents
    ]

@router.post("/{agent_id}/heartbeat")
async def heartbeat(
    agent_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    
    agent.last_seen_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}