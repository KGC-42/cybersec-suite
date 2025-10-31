"use client";

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface Alert {
  id: number;
  source: string;
  severity: string;
  timestamp: string;
  title: string;
  description: string;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/events/`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        setAlerts(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500'
    };
    return colors[severity?.toLowerCase()] || 'bg-gray-500';
  };

  return (
    <div className="min-h-screen bg-slate-900 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-8">GuardianOS Security Alerts</h1>
        
        {loading ? (
          <div className="text-white">Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-12 text-center">
              <div className="text-6xl mb-4">✓</div>
              <p className="text-slate-300 text-xl font-semibold mb-2">All Clear!</p>
              <p className="text-slate-400">No security alerts detected</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-4">
            {alerts.map((alert) => (
              <Card key={alert.id} className="bg-slate-800 border-slate-700 hover:border-violet-500 transition-colors">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-white text-lg capitalize">{alert.source?.replace(/_/g, " ") || "Security Event"}</CardTitle>
                    <Badge className={`${getSeverityColor(alert.severity)} text-white`}>
                      {alert.severity}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-slate-300 mb-2">{alert.title}</p>
                  <p className="text-slate-500 text-sm">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
