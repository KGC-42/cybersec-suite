'use client';

import { useState } from 'react';
import { OrganizationMember, MemberRole } from '../types';
import { removeMember, updateMemberRole } from '../api';
import { RoleSelector } from './RoleSelector';

interface MemberListProps {
  members: OrganizationMember[];
  orgId: string;
  currentUserId: string;
  onUpdate: () => void;
}

export function MemberList({ members, orgId, currentUserId, onUpdate }: MemberListProps) {
  const [loading, setLoading] = useState<string | null>(null);

  async function handleRoleChange(member: OrganizationMember, newRole: MemberRole) {
    if (member.user.id === currentUserId) {
      alert("You cannot change your own role");
      return;
    }

    if (member.role === MemberRole.OWNER) {
      alert("Cannot change owner's role");
      return;
    }

    try {
      setLoading(member.id);
      await updateMemberRole(orgId, member.user.id, newRole);
      onUpdate();
    } catch (error: any) {
      alert(error.message || 'Failed to update role');
    } finally {
      setLoading(null);
    }
  }

  async function handleRemove(member: OrganizationMember) {
    if (member.user.id === currentUserId) {
      alert("You cannot remove yourself");
      return;
    }

    if (member.role === MemberRole.OWNER) {
      alert("Cannot remove owner");
      return;
    }

    if (!confirm(`Remove ${member.user.email} from this organization?`)) {
      return;
    }

    try {
      setLoading(member.id);
      await removeMember(orgId, member.user.id);
      onUpdate();
    } catch (error: any) {
      alert(error.message || 'Failed to remove member');
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
              Member
            </th>
            <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
              Role
            </th>
            <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
              Joined
            </th>
            <th className="text-right py-3 px-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {members.map((member) => {
            const isCurrentUser = member.user.id === currentUserId;
            const isOwner = member.role === MemberRole.OWNER;
            const isLoading = loading === member.id;

            return (
              <tr
                key={member.id}
                className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50"
              >
                <td className="py-3 px-4">
                  <div>
                    <div className="font-medium text-gray-900 dark:text-gray-100">
                      {member.user.full_name || member.user.email}
                      {isCurrentUser && (
                        <span className="ml-2 text-xs text-purple-600 dark:text-purple-400">
                          (You)
                        </span>
                      )}
                    </div>
                    {member.user.full_name && (
                      <div className="text-sm text-gray-500">
                        {member.user.email}
                      </div>
                    )}
                  </div>
                </td>
                <td className="py-3 px-4">
                  <RoleSelector
                    value={member.role}
                    onChange={(role) => handleRoleChange(member, role)}
                    disabled={isCurrentUser || isOwner || isLoading}
                  />
                </td>
                <td className="py-3 px-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(member.joined_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4 text-right">
                  {!isCurrentUser && !isOwner && (
                    <button
                      onClick={() => handleRemove(member)}
                      disabled={isLoading}
                      className="text-sm text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 disabled:opacity-50"
                    >
                      {isLoading ? 'Removing...' : 'Remove'}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}