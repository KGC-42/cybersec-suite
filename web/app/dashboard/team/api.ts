// API service for multi-org operations

import { Organization, OrganizationMember, OrganizationInvitation, InviteMemberRequest, CreateOrganizationRequest } from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

function getAuthHeaders() {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    'Authorization': token ? `Bearer ${token}` : '',
  };
}

// Organizations
export async function getOrganizations(): Promise<Organization[]> {
  const response = await fetch(`${API_URL}/api/v1/orgs`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error('Failed to fetch organizations');
  return response.json();
}

export async function getOrganization(orgId: string): Promise<Organization> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error('Failed to fetch organization');
  return response.json();
}

export async function createOrganization(data: CreateOrganizationRequest): Promise<Organization> {
  const response = await fetch(`${API_URL}/api/v1/orgs`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to create organization');
  return response.json();
}

export async function updateOrganization(orgId: string, data: Partial<Organization>): Promise<Organization> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}`, {
    method: 'PATCH',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to update organization');
  return response.json();
}

// Members
export async function getMembers(orgId: string): Promise<OrganizationMember[]> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}/members`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error('Failed to fetch members');
  return response.json();
}

export async function inviteMember(orgId: string, data: InviteMemberRequest): Promise<OrganizationInvitation> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}/invitations`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to invite member');
  }
  return response.json();
}

export async function removeMember(orgId: string, userId: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}/members/${userId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error('Failed to remove member');
}

export async function updateMemberRole(orgId: string, userId: string, role: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/v1/orgs/${orgId}/members/${userId}/role`, {
    method: 'PATCH',
    headers: getAuthHeaders(),
    body: JSON.stringify({ role }),
  });
  if (!response.ok) throw new Error('Failed to update member role');
}