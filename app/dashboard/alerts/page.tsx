'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import axios, { AxiosError } from 'axios';

interface SecurityEvent {
  id: number;
  agent_id: number;
  event_type: string;
  severity: string;
  description: string;
  details: Record<string, unknown>;
  created_at: string;
  source?: string; // Added source field
}

interface ApiErrorResponse {
  detail?: string;
  message?: string;
}

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';
type SourceType = 'all' | 'clamav' | 'phishing' | 'darkweb';

export default function AlertsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [sourceFilter, setSourceFilter] = useState<SourceType>('all');
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());

  const fetchEvents = useCallback(async () => {
    try {
      setLoading(true);
      setError('');

      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('Not authenticated');
      }

      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      if (!apiUrl) {
        throw new Error('API URL not configured');
      }

      const response = await axios.get<SecurityEvent[]>(
        `${apiUrl}/api/v1/events/`,
        {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 10000
        }
      );

      const eventData = Array.isArray(response.data) ? response.data : [];
      setEvents(eventData);
    } catch (err) {
      console.error('Error fetching events:', err);

      if (axios.isAxiosError(err)) {
        const axiosError = err as AxiosError<ApiErrorResponse>;

        if (axiosError.response?.status === 401) {
          setError('Authentication expired. Please log in again.');
          localStorage.removeItem('token');
        } else if (axiosError.response?.status === 403) {
          setError('Access denied. You do not have permission to view alerts.');
        } else if (axiosError.code === 'ECONNABORTED') {
          setError('Request timeout. Please try again.');
        } else if (axiosError.response?.status === 500) {
          setError('Server error. Please try again later.');
        } else {
          setError(
            axiosError.response?.data?.detail ||
            axiosError.response?.data?.message ||
            axiosError.message ||
            'Failed to load alerts'
          );
        }
      } else {
        setError(err instanceof Error ? err.message : 'An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEvents();

    const interval = setInterval(fetchEvents, 30000);
    return () => clearInterval(interval);
  }, [fetchEvents]);

  const getSourceFromEventType = useCallback((eventType: string): SourceType => {
    const type = eventType.toLowerCase();
    if (type.includes('malware') || type.includes('virus')) return 'clamav';
    if (type.includes('phishing')) return 'phishing';
    if (type.includes('breach') || type.includes('darkweb') || type.includes('dark_web')) return 'darkweb';
    return 'clamav'; // Default
  }, []);

  const getSourceColor = useCallback((source: SourceType): string => {
    const colorMap: Record<SourceType, string> = {
      clamav: 'bg-orange-100 text-orange-800 border-orange-300',
      phishing: 'bg-red-100 text-red-800 border-red-300',
      darkweb: 'bg-red-100 text-red-800 border-red-300',
      all: 'bg-gray-100 text-gray-800 border-gray-300',
    };
    return colorMap[source] || colorMap.all;
  }, []);

  const getSourceIcon = useCallback((source: SourceType): string => {
    const iconMap: Record<SourceType, string> = {
      clamav: '🛡️',
      phishing: '🎣',
      darkweb: '🕷️',
      all: '📋',
    };
    return iconMap[source] || iconMap.all;
  }, []);

  const getSourceLabel = useCallback((source: SourceType): string => {
    const labelMap: Record<SourceType, string> = {
      clamav: 'ClamAV',
      phishing: 'Phishing',
      darkweb: 'Dark Web',
      all: 'All Sources',
    };
    return labelMap[source] || 'Unknown';
  }, []);

  const getSeverityColor = useCallback((severity: string): string => {
    if (!severity) return 'bg-gray-100 text-gray-800 border-gray-200';

    const severityLevel = severity.toLowerCase() as SeverityLevel;
    const colorMap: Record<SeverityLevel, string> = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
    };

    return colorMap[severityLevel] || 'bg-gray-100 text-gray-800 border-gray-200';
  }, []);

  const getSeverityIcon = useCallback((severity: string): string => {
    if (!severity) return '📋';

    const severityLevel = severity.toLowerCase() as SeverityLevel;
    const iconMap: Record<SeverityLevel, string> = {
      critical: '🚨',
      high: '⚠️',
      medium: '⚡',
      low: 'ℹ️',
    };

    return iconMap[severityLevel] || '📋';
  }, []);

  const getEventIcon = useCallback((eventType: string): string => {
    if (!eventType) return '🔔';

    const typeMap: Record<string, string> = {
      malware_detected: '🦠',
      phishing_detected: '🎣',
      network_anomaly: '🌐',
      suspicious_process: '⚙️',
      login_failure: '🔐',
      file_modification: '📄',
      privilege_escalation: '⬆️',
      data_breach: '💥',
    };

    return typeMap[eventType.toLowerCase()] || '🔔';
  }, []);

  const formatDate = useCallback((dateString: string): string => {
    if (!dateString) return 'Unknown';

    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'Invalid date';

      return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      }).format(date);
    } catch {
      return 'Invalid date';
    }
  }, []);

  const getTimeAgo = useCallback((dateString: string): string => {
    if (!dateString) return 'Unknown';

    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'Invalid date';

      const now = new Date();
      const diffSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

      if (diffSeconds < 0) return 'Future';
      if (diffSeconds < 60) return `${diffSeconds}s ago`;
      if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
      if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
      return `${Math.floor(diffSeconds / 86400)}d ago`;
    } catch {
      return 'Invalid date';
    }
  }, []);

  const getSeverityBorderColor = useCallback((severity: string): string => {
    if (!severity) return 'border-l-gray-400';

    const severityLevel = severity.toLowerCase() as SeverityLevel;
    const colorMap: Record<SeverityLevel, string> = {
      critical: 'border-l-red-500',
      high: 'border-l-orange-500',
      medium: 'border-l-yellow-500',
      low: 'border-l-blue-500',
    };

    return colorMap[severityLevel] || 'border-l-gray-400';
  }, []);

  const toggleEventExpansion = useCallback((eventId: number) => {
    setExpandedEvents(prev => {
      const newSet = new Set(prev);
      if (newSet.has(eventId)) {
        newSet.delete(eventId);
      } else {
        newSet.add(eventId);
      }
      return newSet;
    });
  }, []);

  const filteredEvents = useMemo(() => {
    if (sourceFilter === 'all') return events;
    
    return events.filter(event => {
      const eventSource = getSourceFromEventType(event.event_type);
      return eventSource === sourceFilter;
    });
  }, [events, sourceFilter, getSourceFromEventType]);

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    filteredEvents.forEach(event => {
      if (event.severity) {
        const severity = event.severity.toLowerCase() as SeverityLevel;
        if (severity in counts) {
          counts[severity]++;
        }
      }
    });

    return counts;
  }, [filteredEvents]);

  const sourceCounts = useMemo(() => {
    const counts: Record<SourceType, number> = {
      all: events.length,
      clamav: 0,
      phishing: 0,
      darkweb: 0,
    };

    events.forEach(event => {
      const source = getSourceFromEventType(event.event_type);
      counts[source]++;
    });

    return counts;
  }, [events, getSourceFromEventType]);

  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) => {
      const severityOrder: Record<string, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
      };

      const aSeverity = severityOrder[a.severity?.toLowerCase()] || 0;
      const bSeverity = severityOrder[b.severity?.toLowerCase()] || 0;

      if (aSeverity !== bSeverity) {
        return bSeverity - aSeverity;
      }

      const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
      const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;

      return bTime - aTime;
    });
  }, [filteredEvents]);

  const handleRefresh = useCallback(() => {
    void fetchEvents();
  }, [fetchEvents]);

  if (loading && events.length === 0) {
    return (
      <div className="p-8">
        <h1 className="text-3xl font-bold mb-6">Security Alerts</h1>
        <div className="flex items-center justify-center min-h-64">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4" aria-hidden="true"></div>
            <div className="text-gray-600">Loading alerts...</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold text-gray-900">Security Alerts</h1>
        <button
          onClick={handleRefresh}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          type="button"
          disabled={loading}
          aria-label="Refresh alerts"
        >
          <span className={loading ? 'animate-spin' : ''} aria-hidden="true">🔄</span> Refresh
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-100 text-red-700 rounded-lg border border-red-200" role="alert">
          <div className="flex items-center">
            <span className="mr-2" aria-hidden="true">⚠️</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Source Filter Dropdown */}
      <div className="mb-6 bg-white rounded-lg shadow-sm border p-4">
        <label htmlFor="source-filter" className="block text-sm font-medium text-gray-700 mb-2">
          Filter by Source
        </label>
        <select
          id="source-filter"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as SourceType)}
          className="block w-full md:w-64 px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        >
          <option value="all">All Sources ({sourceCounts.all})</option>
          <option value="clamav">🛡️ ClamAV - Malware ({sourceCounts.clamav})</option>
          <option value="phishing">🎣 Phishing Detection ({sourceCounts.phishing})</option>
          <option value="darkweb">🕷️ Dark Web Monitoring ({sourceCounts.darkweb})</option>
        </select>
      </div>

      {events.length > 0 && (
        <div className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {(Object.entries(severityCounts) as [SeverityLevel, number][]).map(([severity, count]) => {
            const colorClasses = {
              critical: 'bg-red-50 border-red-100 text-red-600',
              high: 'bg-orange-50 border-orange-100 text-orange-600',
              medium: 'bg-yellow-50 border-yellow-100 text-yellow-600',
              low: 'bg-blue-50 border-blue-100 text-blue-600',
            };

            const textClasses = {
              critical: 'text-red-700',
              high: 'text-orange-700',
              medium: 'text-yellow-700',
              low: 'text-blue-700',
            };

            return (
              <div key={severity} className={`rounded-lg p-4 border ${colorClasses[severity]}`}>
                <div className="text-sm font-medium capitalize">
                  {severity}
                </div>
                <div className={`text-2xl font-bold ${textClasses[severity]}`}>
                  {count}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {sortedEvents.length === 0 ? (
        <div className="bg-white rounded-lg shadow-sm border p-12 text-center">
          <div className="text-green-400 text-6xl mb-4" aria-hidden="true">✅</div>
          <h2 className="text-2xl font-semibold mb-3 text-gray-900">All Clear!</h2>
          <p className="text-gray-600 text-lg">
            {sourceFilter === 'all' 
              ? 'No security alerts detected. Your systems are protected.'
              : `No ${getSourceLabel(sourceFilter)} alerts detected.`}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {sortedEvents.map((event) => {
            const eventSource = getSourceFromEventType(event.event_type);
            const isExpanded = expandedEvents.has(event.id);
            
            return (
              <div
                key={event.id}
                className={`bg-white rounded-lg shadow-md border-l-4 p-6 hover:shadow-lg transition-shadow ${getSeverityBorderColor(event.severity)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className="text-3xl flex-shrink-0" aria-hidden="true">
                      {getEventIcon(event.event_type)}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-3 mb-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(event.severity)}`}>
                          <span aria-hidden="true">{getSeverityIcon(event.severity)}</span>{' '}
                          {event.severity ? event.severity.toUpperCase() : 'UNKNOWN'}
                        </span>
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getSourceColor(eventSource)}`}>
                          <span aria-hidden="true">{getSourceIcon(eventSource)}</span>{' '}
                          {getSourceLabel(eventSource)}
                        </span>
                        <span className="text-sm text-gray-500 bg-gray-100 px-2 py-1 rounded">
                          Agent #{event.agent_id}
                        </span>
                        <span className="text-sm text-gray-500">
                          {getTimeAgo(event.created_at)}
                        </span>
                      </div>

                      <h3 className="text-lg font-bold text-gray-900 mb-2 break-words">
                        {event.description || 'Security Event'}
                      </h3>

                      {event.event_type && (
                        <div className="text-sm text-gray-600 mb-3">
                          <span className="font-medium">Event Type:</span>{' '}
                          <span className="capitalize bg-gray-50 px-2 py-1 rounded">
                            {event.event_type.replace(/_/g, ' ')}
                          </span>
                        </div>
                      )}

                      {event.details && Object.keys(event.details).length > 0 && (
                        <div className="mt-4">
                          <button
                            onClick={() => toggleEventExpansion(event.id)}
                            className="text-sm text-blue-600 hover:text-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-medium flex items-center gap-2"
                          >
                            <span>{isExpanded ? '▼' : '▶'}</span>
                            {isExpanded ? 'Hide' : 'View'} Breach Information & Technical Details
                          </button>
                          
                          {isExpanded && (
                            <div className="mt-3 p-4 bg-gray-50 rounded-lg border space-y-4">
                              {/* Breach Information Section */}
                              {eventSource === 'darkweb' && (
                                <div className="border-b border-gray-200 pb-4">
                                  <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                                    <span>🔍</span> Breach Information
                                  </h4>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                                    {event.details.breach_name && (
                                      <div>
                                        <span className="font-medium text-gray-700">Breach Name:</span>
                                        <span className="ml-2 text-gray-600">{String(event.details.breach_name)}</span>
                                      </div>
                                    )}
                                    {event.details.domain && (
                                      <div>
                                        <span className="font-medium text-gray-700">Domain:</span>
                                        <span className="ml-2 text-gray-600">{String(event.details.domain)}</span>
                                      </div>
                                    )}
                                    {event.details.breach_date && (
                                      <div>
                                        <span className="font-medium text-gray-700">Breach Date:</span>
                                        <span className="ml-2 text-gray-600">{String(event.details.breach_date)}</span>
                                      </div>
                                    )}
                                    {event.details.pwn_count && (
                                      <div>
                                        <span className="font-medium text-gray-700">Accounts Affected:</span>
                                        <span className="ml-2 text-red-600 font-semibold">
                                          {Number(event.details.pwn_count).toLocaleString()}
                                        </span>
                                      </div>
                                    )}
                                  </div>
                                  {event.details.data_classes && Array.isArray(event.details.data_classes) && (
                                    <div className="mt-3">
                                      <span className="font-medium text-gray-700">Compromised Data:</span>
                                      <div className="flex flex-wrap gap-1 mt-1">
                                        {event.details.data_classes.map((dataClass, idx) => (
                                          <span key={idx} className="bg-red-100 text-red-800 text-xs px-2 py-1 rounded border border-red-200">
                                            {String(dataClass)}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                              
                              {/* Technical Details Section */}
                              <div>
                                <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                                  <span>⚙️</span> Technical Details
                                </h4>
                                <pre className="whitespace-pre-wrap overflow-auto max-h-64 text-xs font-mono text-gray-700">
                                  {JSON.stringify(event.details, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      <div className="mt-4 pt-3 border-t border-gray-100 text-xs text-gray-500">
                        <span className="font-medium">Detected:</span> {formatDate(event.created_at)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}