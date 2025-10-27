'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';

interface SecurityEvent {
  id: number;
  agent_id: number;
  event_type: string;
  severity: string;
  description: string;
  details: any;
  created_at: string;
}

export default function AlertsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchEvents = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setError('Not authenticated');
        return;
      }

      const response = await axios.get(
        `${process.env.NEXT_PUBLIC_API_URL}/api/v1/events/`,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      setEvents(response.data);
      setError('');
    } catch (err: any) {
      console.error('Error fetching events:', err);
      setError(err.response?.data?.detail || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();

    // Refresh every 30 seconds
    const interval = setInterval(fetchEvents, 30000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    if (!severity) return 'bg-gray-100 text-gray-800 border-gray-200';
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    if (!severity) return '📋';
    switch (severity.toLowerCase()) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '⚡';
      case 'low': return 'ℹ️';
      default: return '📋';
    }
  };

  const getEventIcon = (eventType: string) => {
    if (!eventType) return '🔔';
    switch (eventType.toLowerCase()) {
      case 'malware_detected': return '🦠';
      case 'phishing_detected': return '🎣';
      case 'network_anomaly': return '🌐';
      case 'suspicious_process': return '⚙️';
      default: return '🔔';
    }
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getTimeAgo = (dateString: string) => {
    if (!dateString) return 'Unknown';
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
        <h1 className="text-3xl font-bold mb-6">Security Alerts</h1>
        <div className="text-gray-600">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Security Alerts</h1>
        <button
          onClick={fetchEvents}
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

      {events.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <div className="text-gray-400 text-6xl mb-4">✅</div>
          <h2 className="text-xl font-semibold mb-2">All Clear!</h2>
          <p className="text-gray-600">
            No security alerts detected. Your devices are protected.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {events.map((event) => (
            <div
              key={event.id}
              className={`bg-white rounded-lg shadow-lg border-l-4 p-6 ${getSeverityColor(event.severity)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  {/* Icon */}
                  <div className="text-3xl">
                    {getEventIcon(event.event_type)}
                  </div>

                  {/* Content */}
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(event.severity)}`}>
                        {getSeverityIcon(event.severity)} {event.severity ? event.severity.toUpperCase() : 'UNKNOWN'}
                      </span>
                      <span className="text-sm text-gray-500">
                        Agent #{event.agent_id}
                      </span>
                      <span className="text-sm text-gray-500">
                        {getTimeAgo(event.created_at)}
                      </span>
                    </div>

                    <h3 className="text-lg font-bold text-gray-900 mb-2">
                      {event.description || 'Security Event'}
                    </h3>

                    {event.event_type && (
                      <div className="text-sm text-gray-600 mb-3">
                        <span className="font-medium">Event Type:</span>{' '}
                        <span className="capitalize">{event.event_type.replace('_', ' ')}</span>
                      </div>
                    )}

                    {/* Details */}
                    {event.details && Object.keys(event.details).length > 0 && (
                      <details className="mt-3">
                        <summary className="cursor-pointer text-sm text-blue-600 hover:text-blue-800 font-medium">
                          View Details
                        </summary>
                        <div className="mt-2 p-3 bg-gray-50 rounded text-xs font-mono">
                          <pre className="whitespace-pre-wrap">
                            {JSON.stringify(event.details, null, 2)}
                          </pre>
                        </div>
                      </details>
                    )}

                    <div className="mt-3 text-xs text-gray-400">
                      {formatDate(event.created_at)}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats Summary */}
      {events.length > 0 && (
        <div className="mt-8 grid gap-4 md:grid-cols-4">
          <div className="bg-red-50 rounded-lg p-4">
            <div className="text-red-600 text-sm font-medium">Critical</div>
            <div className="text-2xl font-bold text-red-700">
              {events.filter(e => e.severity && e.severity.toLowerCase() === 'critical').length}
            </div>
          </div>
          <div className="bg-orange-50 rounded-lg p-4">
            <div className="text-orange-600 text-sm font-medium">High</div>
            <div className="text-2xl font-bold text-orange-700">
              {events.filter(e => e.severity && e.severity.toLowerCase() === 'high').length}
            </div>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4">
            <div className="text-yellow-600 text-sm font-medium">Medium</div>
            <div className="text-2xl font-bold text-yellow-700">
              {events.filter(e => e.severity && e.severity.toLowerCase() === 'medium').length}
            </div>
          </div>
          <div className="bg-blue-50 rounded-lg p-4">
            <div className="text-blue-600 text-sm font-medium">Low</div>
            <div className="text-2xl font-bold text-blue-700">
              {events.filter(e => e.severity && e.severity.toLowerCase() === 'low').length}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}