"""
Role-Based Access Control (RBAC) System
"""
from functools import wraps
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from typing import Optional, Dict, List
import json
from pathlib import Path


PERMISSIONS = {
    "owner": {
        "org.settings.update": True,
        "org.delete": True,
        "org.members.invite": True,
        "org.members.remove": True,
        "org.members.role.change": True,
        "org.billing.manage": True,
        "resource.create": True,
        "resource.read": True,
        "resource.update": True,
        "resource.delete": True
    },
    "admin": {
        "org.settings.update": True,
        "org.members.invite": True,
        "org.members.remove": True,
        "resource.create": True,
        "resource.read": True,
        "resource.update": True,
        "resource.delete": True
    },
    "member": {
        "resource.create": True,
        "resource.read": True,
        "resource.update": True,
        "resource.delete": False
    },
    "viewer": {
        "resource.read": True
    }
}


def has_permission(role: str, permission: str, custom_permissions: Optional[Dict] = None) -> bool:
    """
    Check if a role has a specific permission
    
    Args:
        role: User's role (owner, admin, member, viewer)
        permission: Permission to check (e.g., "resource.delete")
        custom_permissions: Optional app-specific permissions
    
    Returns:
        True if role has permission, False otherwise
    """
    if custom_permissions and permission in custom_permissions:
        return role in custom_permissions[permission]
    
    role_perms = PERMISSIONS.get(role.lower(), {})
    return role_perms.get(permission, False)


def get_user_role_in_org(db: Session, user_id: str, org_id: str):
    """
    Get user's role in an organization
    Must be implemented by the app using this package
    """
    from .models import get_organization_member_model
    from apps.cybersec_suite.backend.app.database import Base
    
    OrganizationMember = get_organization_member_model(Base)
    
    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == org_id,
        OrganizationMember.user_id == user_id
    ).first()
    
    return member.role if member else None


def require_permission(permission: str):
    """
    Decorator to check if user has permission in current org
    
    Usage:
        @router.delete("/agents/{agent_id}")
        @require_permission("resource.delete")
        async def delete_agent(agent_id: str, org_id: str, current_user: dict):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            org_id = kwargs.get('org_id')
            db = kwargs.get('db')
            
            if not current_user or not org_id or not db:
                raise HTTPException(
                    status_code=400,
                    detail="Missing required parameters: current_user, org_id, or db"
                )
            
            user_id = current_user.get('id') if isinstance(current_user, dict) else current_user.id
            role = get_user_role_in_org(db, user_id, org_id)
            
            if not role:
                raise HTTPException(
                    status_code=403,
                    detail="You are not a member of this organization"
                )
            
            if not has_permission(role, permission):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required: {permission}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def check_org_membership(db: Session, user_id: str, org_id: str) -> bool:
    """Check if user is a member of organization"""
    from .models import get_organization_member_model
    from apps.cybersec_suite.backend.app.database import Base
    
    OrganizationMember = get_organization_member_model(Base)
    
    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == org_id,
        OrganizationMember.user_id == user_id
    ).first()
    
    return member is not None


def is_org_owner(db: Session, user_id: str, org_id: str) -> bool:
    """Check if user is the owner of organization"""
    from .models import get_organization_model
    from apps.cybersec_suite.backend.app.database import Base
    
    Organization = get_organization_model(Base)
    
    org = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.owner_id == user_id
    ).first()
    
    return org is not None