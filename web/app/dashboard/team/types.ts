// TypeScript interfaces for multi-org system

export enum OrganizationPlan {
  FREE = 'free',
  PRO = 'pro',
  ENTERPRISE = 'enterprise'
}

export enum MemberRole {
  OWNER = 'owner',
  ADMIN = 'admin',
  MEMBER = 'member',
  VIEWER = 'viewer'
}

export enum InvitationStatus {
  PENDING = 'pending',
  ACCEPTED = 'accepted',
  EXPIRED = 'expired',
  REVOKED = 'revoked'
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  plan: OrganizationPlan;
  billing_email?: string;
  max_members: number;
  max_resources: number;
  created_at: string;
  updated_at: string;
}

export interface UserBasic {
  id: string;
  email: string;
  full_name?: string;
}

export interface OrganizationMember {
  id: string;
  role: MemberRole;
  joined_at: string;
  user: UserBasic;
}

export interface OrganizationInvitation {
  id: string;
  org_id: string;
  email: string;
  role: MemberRole;
  status: InvitationStatus;
  token: string;
  invited_by: string;
  created_at: string;
  expires_at: string;
  accepted_at?: string;
  is_expired: boolean;
}

export interface InviteMemberRequest {
  email: string;
  role: MemberRole;
}

export interface CreateOrganizationRequest {
  name: string;
  slug?: string;
}