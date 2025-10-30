from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    ForeignKey,
    Enum,
    Boolean,
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.database import Base

# -----------------------------
# Enums
# -----------------------------

class AgentPlatform(str, enum.Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"

class EventSource(str, enum.Enum):
    CLAMAV = "clamav"
    SURICATA = "suricata"
    PHISHING = "phishing"
    DARKWEB = "darkweb"
    AGENT = "agent"

class EventSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# -----------------------------
# Models
# -----------------------------

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    notification_email = Column(String(255))  # Email for alerts (can be different)
    email_notifications_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # Link to user
    organization_id = Column(Integer, nullable=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(Enum(AgentPlatform), nullable=True)
    arch = Column(String(20))
    agent_version = Column(String(20))
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", backref="agents")
    events = relationship("SecurityEvent", back_populates="agent")

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey("agents.id"))
    organization_id = Column(Integer, nullable=True)
    source = Column(Enum(EventSource))
    severity = Column(Enum(EventSeverity))
    title = Column(String(500), nullable=False)
    description = Column(String(2000))
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)
    
    agent = relationship("Agent", back_populates="events")