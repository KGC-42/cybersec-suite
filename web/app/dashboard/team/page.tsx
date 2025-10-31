'use client';

import { useEffect, useState } from 'react';
import { Organization, OrganizationMember } from './types';
import { getOrganization, getMembers } from './api';
import { OrgSwitcher } from './components/OrgSwitcher';
import { MemberList } from './components/MemberList';
import { InviteModal } from './components/InviteModal';

export default function TeamPage() {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [currentUserId, setCurrentUserId] = useState('');

  useEffect(() => {
    loadData();
    loadCurrentUser();
  }, []);

  async function loadCurrentUser() {
    // Get current user from localStorage (set during login)
    const userStr = localStorage.getItem('user');
    if (userStr) {
      const user = JSON.parse(userStr);
      setCurrentUserId(user.id);
    }
  }

  async function loadData() {
    try {
      setLoading(true);
      const orgId = localStorage.getItem('currentOrgId');
      
      if (!orgId) {
        console.log('No organization selected');
        return;
      }

      const [org, memberList] = await Promise.all([
        getOrganization(orgId),
        getMembers(orgId),
      ]);

      setOrganization(org);
      setMembers(memberList);
    } catch (error) {
      console.error('Failed to load team data:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Loading team...</p>
        </div>
      </div>
    );
  }

  if (!organization) {
    return (
      <div className="p-8">
        <div className="text-center py-12">
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
            No Organization Found
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            You need to create or join an organization first.
          </p>
          <button
            onClick={() => window.location.href = '/dashboard'}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
              Team Management
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Manage members and roles for {organization.name}
            </p>
          </div>
          <OrgSwitcher />
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">
              Total Members
            </div>
            <div className="text-3xl font-bold text-gray-900 dark:text-gray-100">
              {members.length}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              of {organization.max_members} max
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">
              Organization Plan
            </div>
            <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
              {organization.plan.toUpperCase()}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">
              Created
            </div>
            <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              {new Date(organization.created_at).toLocaleDateString('en-US', {
                month: 'long',
                day: 'numeric',
                year: 'numeric'
              })}
            </div>
          </div>
        </div>

        {/* Members Section */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                  Team Members
                </h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Manage roles and permissions for your team
                </p>
              </div>
              <button
                onClick={() => setShowInviteModal(true)}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg flex items-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Invite Member
              </button>
            </div>
          </div>

          <MemberList
            members={members}
            orgId={organization.id}
            currentUserId={currentUserId}
            onUpdate={loadData}
          />
        </div>
      </div>

      <InviteModal
        orgId={organization.id}
        isOpen={showInviteModal}
        onClose={() => setShowInviteModal(false)}
        onSuccess={loadData}
      />
    </div>
  );
}