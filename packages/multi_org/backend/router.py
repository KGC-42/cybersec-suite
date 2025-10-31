"""
FastAPI Router for Multi-Organization System
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
import secrets
import uuid
from datetime import datetime, timedelta

from .schemas import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationWithMembers,
    MemberResponse,
    MemberRoleUpdate,
    InvitationCreate,
    InvitationResponse,
    InvitationAccept,
    MemberRole
)
from .permissions import require_permission, check_org_membership, is_org_owner


router = APIRouter(prefix="/api/v1/orgs", tags=["organizations"])


def get_db():
    """Dependency to get database session - must be overridden by app"""
    raise NotImplementedError("get_db must be provided by the app")


def get_current_user():
    """Dependency to get current user - must be overridden by app"""
    raise NotImplementedError("get_current_user must be provided by the app")


def get_models():
    """Get models dynamically - import from actual app location"""
    try:
        from apps.cybersec_suite.backend.app.database import Base
        from apps.cybersec_suite.backend.app.models.user import User
    except ImportError:
        import sys
        from pathlib import Path
        app_path = Path(__file__).parent.parent.parent.parent / "apps" / "cybersec-suite" / "backend"
        sys.path.insert(0, str(app_path))
        from app.database import Base
        from app.models.user import User
    
    from packages.multi_org.backend.models import (
        get_organization_model,
        get_organization_member_model,
        get_organization_invitation_model
    )
    
    Organization = get_organization_model(Base)
    OrganizationMember = get_organization_member_model(Base)
    OrganizationInvitation = get_organization_invitation_model(Base)
    
    return Organization, OrganizationMember, OrganizationInvitation, User


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new organization - The current user becomes the owner"""
    Organization, OrganizationMember, _, _ = get_models()
    
    existing = db.query(Organization).filter(Organization.slug == org_data.slug).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization with slug '{org_data.slug}' already exists"
        )
    
    new_org = Organization(
        id=uuid.uuid4(),
        name=org_data.name,
        slug=org_data.slug,
        owner_id=uuid.UUID(current_user['id'])
    )
    db.add(new_org)
    db.flush()
    
    owner_membership = OrganizationMember(
        id=uuid.uuid4(),
        org_id=new_org.id,
        user_id=uuid.UUID(current_user['id']),
        role=MemberRole.OWNER
    )
    db.add(owner_membership)
    db.commit()
    db.refresh(new_org)
    
    return new_org


@router.get("/", response_model=List[OrganizationResponse])
async def list_organizations(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all organizations where user is a member"""
    Organization, OrganizationMember, _, _ = get_models()
    
    user_id = uuid.UUID(current_user['id'])
    
    orgs = db.query(Organization).join(OrganizationMember).filter(
        OrganizationMember.user_id == user_id
    ).all()
    
    return orgs


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get organization details"""
    Organization, _, _, _ = get_models()
    
    if not check_org_membership(db, current_user['id'], org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization"
        )
    
    org = db.query(Organization).filter(Organization.id == uuid.UUID(org_id)).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    return org


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    org_data: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update organization settings (admin/owner only)"""
    Organization, _, _, _ = get_models()
    
    org = db.query(Organization).filter(Organization.id == uuid.UUID(org_id)).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    if org_data.name:
        org.name = org_data.name
    if org_data.billing_email:
        org.billing_email = org_data.billing_email
    if org_data.plan:
        org.plan = org_data.plan
    
    org.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(org)
    
    return org


@router.get("/{org_id}/members", response_model=List[MemberResponse])
async def list_members(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all members of an organization"""
    _, OrganizationMember, _, _ = get_models()
    
    if not check_org_membership(db, current_user['id'], org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization"
        )
    
    members = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == uuid.UUID(org_id)
    ).all()
    
    return members


@router.post("/{org_id}/invitations", response_model=InvitationResponse)
async def invite_member(
    org_id: str,
    invitation_data: InvitationCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Invite a new member to the organization"""
    _, OrganizationMember, OrganizationInvitation, User = get_models()
    
    existing_member = db.query(OrganizationMember).join(User).filter(
        OrganizationMember.org_id == uuid.UUID(org_id),
        User.email == invitation_data.email
    ).first()
    
    if existing_member:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member of this organization"
        )
    
    token = secrets.token_urlsafe(32)
    
    invitation = OrganizationInvitation(
        id=uuid.uuid4(),
        org_id=uuid.UUID(org_id),
        email=invitation_data.email,
        role=invitation_data.role,
        token=token,
        invited_by=uuid.UUID(current_user['id'])
    )
    
    db.add(invitation)
    db.commit()
    db.refresh(invitation)
    
    return invitation


@router.delete("/{org_id}/members/{user_id}")
async def remove_member(
    org_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Remove a member from the organization"""
    _, OrganizationMember, _, _ = get_models()
    
    if is_org_owner(db, user_id, org_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove organization owner"
        )
    
    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == uuid.UUID(org_id),
        OrganizationMember.user_id == uuid.UUID(user_id)
    ).first()
    
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found"
        )
    
    db.delete(member)
    db.commit()
    
    return {"message": "Member removed successfully"}


@router.patch("/{org_id}/members/{user_id}/role")
async def update_member_role(
    org_id: str,
    user_id: str,
    role_data: MemberRoleUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update a member's role"""
    _, OrganizationMember, _, _ = get_models()
    
    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == uuid.UUID(org_id),
        OrganizationMember.user_id == uuid.UUID(user_id)
    ).first()
    
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found"
        )
    
    if member.role == MemberRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change owner's role"
        )
    
    member.role = role_data.role
    db.commit()
    
    return {"message": "Role updated successfully"}