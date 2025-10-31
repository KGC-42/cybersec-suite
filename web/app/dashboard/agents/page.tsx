'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';

interface Agent {
  id: number;
  hostname: string;
  platform: string;
  arch: string;
  agent_version: string;
  last_seen_at: string;
  created_at: string;
  status: string;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchAgents = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setError('Not authenticated');
        return;
      }

      const response = await axios.get(
        `${process.env.NEXT_PUBLIC_API_URL}/api/v1/agents/`,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      setAgents(response.data);
      setError('');
    } catch (err: any) {
      console.error('Error fetching agents:', err);
      setError(err.response?.data?.detail || 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();

    // Refresh every 30 seconds
    const interval = setInterval(fetchAgents, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (lastSeen: string) => {
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    const diffMinutes = (now.getTime() - lastSeenDate.getTime()) / 1000 / 60;

    if (diffMinutes < 2) return 'bg-green-500';
    if (diffMinutes < 5) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getStatusText = (lastSeen: string) => {
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    const diffMinutes = (now.getTime() - lastSeenDate.getTime()) / 1000 / 60;

    if (diffMinutes < 2) return 'Online';
    if (diffMinutes < 5) return 'Away';
    return 'Offline';
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffSeconds < 60) return `${diffSeconds}s ago`;
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
  };

  if (loading) {
    return (
      <div className="p-8">
        <h1 className="text-3xl font-bold mb-6">Agents</h1>
        <div className="text-gray-600">Loading agents...</div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Agents</h1>
        <button
          onClick={fetchAgents}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          🔄 Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}

      {agents.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <div className="text-gray-400 text-6xl mb-4">🖥️</div>
          <h2 className="text-xl font-semibold mb-2">No Agents Yet</h2>
          <p className="text-gray-600">
            Install the CyberSec agent on your devices to see them here.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {agents.map((agent) => (
            <div
              key={agent.id}
              className="bg-white rounded-lg shadow-lg p-6 hover:shadow-xl transition-shadow"
            >
              {/* Status Indicator */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${getStatusColor(agent.last_seen_at)}`} />
                  <span className="font-semibold text-gray-700">
                    {getStatusText(agent.last_seen_at)}
                  </span>
                </div>
                <span className="text-xs text-gray-500">
                  ID: {agent.id}
                </span>
              </div>

              {/* Device Info */}
              <div className="mb-4">
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  {agent.hostname}
                </h3>
                <div className="space-y-1 text-sm text-gray-600">
                  <div className="flex items-center">
                    <span className="w-20 font-medium">Platform:</span>
                    <span className="capitalize">{agent.platform}</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-20 font-medium">Arch:</span>
                    <span>{agent.arch}</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-20 font-medium">Version:</span>
                    <span>{agent.agent_version}</span>
                  </div>
                </div>
              </div>

              {/* Timestamps */}
              <div className="border-t pt-4 space-y-2 text-xs text-gray-500">
                <div>
                  <span className="font-medium">Last Seen:</span>{' '}
                  {getTimeAgo(agent.last_seen_at)}
                </div>
                <div>
                  <span className="font-medium">Registered:</span>{' '}
                  {formatDate(agent.created_at)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats Summary */}
      {agents.length > 0 && (
        <div className="mt-8 grid gap-4 md:grid-cols-3">
          <div className="bg-green-50 rounded-lg p-4">
            <div className="text-green-600 text-sm font-medium">Online</div>
            <div className="text-2xl font-bold text-green-700">
              {agents.filter(a => getStatusText(a.last_seen_at) === 'Online').length}
            </div>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4">
            <div className="text-yellow-600 text-sm font-medium">Away</div>
            <div className="text-2xl font-bold text-yellow-700">
              {agents.filter(a => getStatusText(a.last_seen_at) === 'Away').length}
            </div>
          </div>
          <div className="bg-red-50 rounded-lg p-4">
            <div className="text-red-600 text-sm font-medium">Offline</div>
            <div className="text-2xl font-bold text-red-700">
              {agents.filter(a => getStatusText(a.last_seen_at) === 'Offline').length}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}