"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import re


class OrganizationPlan(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class MemberRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: Optional[str] = Field(None, min_length=2, max_length=50)
    
    @validator('slug', always=True)
    def generate_slug(cls, v, values):
        if v is None and 'name' in values:
            slug = re.sub(r'[^a-z0-9]+', '-', values['name'].lower()).strip('-')
            return slug[:50]
        return v
    
    @validator('slug')
    def validate_slug(cls, v):
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    billing_email: Optional[EmailStr] = None
    plan: Optional[OrganizationPlan] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    owner_id: str
    plan: OrganizationPlan
    billing_email: Optional[str]
    max_members: int
    max_resources: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class OrganizationWithMembers(OrganizationResponse):
    member_count: int
    members: List['MemberResponse']


class UserBasic(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    
    class Config:
        from_attributes = True


class MemberResponse(BaseModel):
    id: str
    role: MemberRole
    joined_at: datetime
    user: UserBasic
    
    class Config:
        from_attributes = True


class MemberRoleUpdate(BaseModel):
    role: MemberRole


class InvitationCreate(BaseModel):
    email: EmailStr
    role: MemberRole = MemberRole.MEMBER


class InvitationResponse(BaseModel):
    id: str
    org_id: str
    email: str
    role: MemberRole
    status: InvitationStatus
    token: str
    invited_by: str
    created_at: datetime
    expires_at: datetime
    accepted_at: Optional[datetime]
    is_expired: bool
    
    class Config:
        from_attributes = True


class InvitationAccept(BaseModel):
    token: str


class PermissionCheck(BaseModel):
    permission: str
    allowed: bool
    reason: Optional[str] = None