'use client';

import { MemberRole } from '../types';

interface RoleSelectorProps {
  value: MemberRole;
  onChange: (role: MemberRole) => void;
  disabled?: boolean;
}

const roleDescriptions = {
  [MemberRole.OWNER]: 'Full control - can delete organization',
  [MemberRole.ADMIN]: 'Manage members and all resources',
  [MemberRole.MEMBER]: 'Create and manage resources',
  [MemberRole.VIEWER]: 'View only access',
};

const roleColors = {
  [MemberRole.OWNER]: 'text-red-600 dark:text-red-400',
  [MemberRole.ADMIN]: 'text-purple-600 dark:text-purple-400',
  [MemberRole.MEMBER]: 'text-blue-600 dark:text-blue-400',
  [MemberRole.VIEWER]: 'text-gray-600 dark:text-gray-400',
};

export function RoleSelector({ value, onChange, disabled }: RoleSelectorProps) {
  return (
    <div className="flex items-center gap-2">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as MemberRole)}
        disabled={disabled}
        className="px-3 py-1.5 border border-gray-300 dark:border-gray-700 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {Object.values(MemberRole).map((role) => (
          <option key={role} value={role}>
            {role.charAt(0).toUpperCase() + role.slice(1)}
          </option>
        ))}
      </select>
      <span className={`text-xs ${roleColors[value]}`} title={roleDescriptions[value]}>
        ●
      </span>
    </div>
  );
}