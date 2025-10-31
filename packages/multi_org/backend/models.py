"""
Universal Multi-Organization Database Models
Compatible with any SQLAlchemy-based application
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Enum as SQLEnum, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum


class OrganizationPlan(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class MemberRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class InvitationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


def get_organization_model(Base):
    """
    Factory function to create Organization model with your app's Base
    
    Usage:
        from your_app.database import Base
        Organization = get_organization_model(Base)
    """
    
    class Organization(Base):
        __tablename__ = "organizations"
        
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        name = Column(String(255), nullable=False)
        slug = Column(String(100), unique=True, nullable=False, index=True)
        owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
        
        plan = Column(SQLEnum(OrganizationPlan), default=OrganizationPlan.FREE, nullable=False)
        billing_email = Column(String(255))
        max_members = Column(Integer, default=5)
        max_resources = Column(Integer, default=10)
        
        settings = Column(Text)
        created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
        invitations = relationship("OrganizationInvitation", back_populates="organization", cascade="all, delete-orphan")
        
        def __repr__(self):
            return f"<Organization {self.name} ({self.slug})>"
    
    return Organization


def get_organization_member_model(Base):
    """Factory function for OrganizationMember model"""
    
    class OrganizationMember(Base):
        __tablename__ = "organization_members"
        
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
        user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
        role = Column(SQLEnum(MemberRole), nullable=False, default=MemberRole.MEMBER)
        
        invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
        joined_at = Column(DateTime, default=datetime.utcnow, nullable=False)
        
        organization = relationship("Organization", back_populates="members")
        user = relationship("User", foreign_keys=[user_id])
        inviter = relationship("User", foreign_keys=[invited_by])
        
        __table_args__ = (
            UniqueConstraint('org_id', 'user_id', name='uq_org_user'),
        )
        
        def __repr__(self):
            return f"<OrganizationMember {self.user_id} in {self.org_id} as {self.role}>"
    
    return OrganizationMember


def get_organization_invitation_model(Base):
    """Factory function for OrganizationInvitation model"""
    
    class OrganizationInvitation(Base):
        __tablename__ = "organization_invitations"
        
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
        org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
        email = Column(String(255), nullable=False, index=True)
        role = Column(SQLEnum(MemberRole), nullable=False, default=MemberRole.MEMBER)
        token = Column(String(255), unique=True, nullable=False, index=True)
        status = Column(SQLEnum(InvitationStatus), default=InvitationStatus.PENDING, nullable=False)
        
        invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
        expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=7), nullable=False)
        accepted_at = Column(DateTime)
        
        organization = relationship("Organization", back_populates="invitations")
        inviter = relationship("User", foreign_keys=[invited_by])
        
        @property
        def is_expired(self):
            return datetime.utcnow() > self.expires_at
        
        def __repr__(self):
            return f"<OrganizationInvitation {self.email} to {self.org_id} ({self.status})>"
    
    return OrganizationInvitation