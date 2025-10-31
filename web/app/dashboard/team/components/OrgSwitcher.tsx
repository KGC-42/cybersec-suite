'use client';

import { useEffect, useState } from 'react';
import { Organization } from '../types';
import { getOrganizations } from '../api';

export function OrgSwitcher() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [currentOrgId, setCurrentOrgId] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadOrganizations();
  }, []);

  async function loadOrganizations() {
    try {
      const orgs = await getOrganizations();
      setOrganizations(orgs);
      
      // Get current org from localStorage or use first org
      const savedOrgId = localStorage.getItem('currentOrgId');
      if (savedOrgId && orgs.find(o => o.id === savedOrgId)) {
        setCurrentOrgId(savedOrgId);
      } else if (orgs.length > 0) {
        setCurrentOrgId(orgs[0].id);
        localStorage.setItem('currentOrgId', orgs[0].id);
      }
    } catch (error) {
      console.error('Failed to load organizations:', error);
    } finally {
      setLoading(false);
    }
  }

  function switchOrg(orgId: string) {
    setCurrentOrgId(orgId);
    localStorage.setItem('currentOrgId', orgId);
    // Reload page to update all data with new org context
    window.location.reload();
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
        <span className="text-sm text-gray-500">Loading...</span>
      </div>
    );
  }

  if (organizations.length === 0) {
    return null;
  }

  const currentOrg = organizations.find(o => o.id === currentOrgId);

  return (
    <div className="relative">
      <select
        value={currentOrgId}
        onChange={(e) => switchOrg(e.target.value)}
        className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
      >
        {organizations.map((org) => (
          <option key={org.id} value={org.id}>
            {org.name}
          </option>
        ))}
      </select>
      {currentOrg && (
        <div className="text-xs text-gray-500 mt-1">
          {currentOrg.plan.toUpperCase()} plan
        </div>
      )}
    </div>
  );
}