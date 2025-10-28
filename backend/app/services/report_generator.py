from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import json
from jinja2 import Template
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from ..models.security_event import SecurityEvent
from ..database import get_db


@dataclass
class SecurityStats:
    total_alerts: int
    severity_breakdown: Dict[str, int]
    source_breakdown: Dict[str, int]
    risk_score: float
    breach_indicators: List[Dict]
    period_start: datetime
    period_end: datetime


class ReportGenerator:
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }

    def generate_weekly_report(self, db: Session) -> SecurityStats:
        """Generate security report for the last 7 days"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = db.query(SecurityEvent).filter(
            and_(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            )
        ).all()
        
        return self._calculate_stats(events, start_date, end_date)

    def _calculate_stats(self, events: List[SecurityEvent], start_date: datetime, end_date: datetime) -> SecurityStats:
        """Calculate statistics from security events"""
        total_alerts = len(events)
        
        # Calculate severity breakdown
        severity_breakdown = defaultdict(int)
        for event in events:
            severity_breakdown[event.severity] += 1
        
        # Calculate source type breakdown
        source_breakdown = defaultdict(int)
        for event in events:
            source_breakdown[event.source_type] += 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(events)
        
        # Perform breach analysis
        breach_indicators = self._analyze_breach_indicators(events)
        
        return SecurityStats(
            total_alerts=total_alerts,
            severity_breakdown=dict(severity_breakdown),
            source_breakdown=dict(source_breakdown),
            risk_score=risk_score,
            breach_indicators=breach_indicators,
            period_start=start_date,
            period_end=end_date
        )

    def _calculate_risk_score(self, events: List[SecurityEvent]) -> float:
        """Calculate overall risk score based on events"""
        if not events:
            return 0.0
        
        total_weight = 0
        for event in events:
            weight = self.severity_weights.get(event.severity, 1)
            total_weight += weight
        
        # Normalize to 0-100 scale
        max_possible = len(events) * self.severity_weights['CRITICAL']
        if max_possible == 0:
            return 0.0
        
        risk_score = (total_weight / max_possible) * 100
        return round(risk_score, 2)

    def _analyze_breach_indicators(self, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze events for potential breach indicators"""
        indicators = []
        
        # Group events by source IP
        ip_events = defaultdict(list)
        for event in events:
            if hasattr(event, 'source_ip') and event.source_ip:
                ip_events[event.source_ip].append(event)
        
        # Check for suspicious patterns
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) > 10:  # High frequency from single IP
                critical_events = [e for e in ip_event_list if e.severity in ['CRITICAL', 'HIGH']]
                if critical_events:
                    indicators.append({
                        'type': 'high_frequency_critical_events',
                        'source_ip': ip,
                        'event_count': len(ip_event_list),
                        'critical_count': len(critical_events),
                        'description': f'High frequency critical events from IP {ip}'
                    })
        
        # Check for authentication failures
        auth_failures = [e for e in events if 'authentication' in e.event_type.lower() and 'fail' in e.event_type.lower()]
        if len(auth_failures) > 20:
            indicators.append({
                'type': 'excessive_auth_failures',
                'event_count': len(auth_failures),
                'description': f'Excessive authentication failures detected: {len(auth_failures)} events'
            })
        
        # Check for data exfiltration patterns
        data_events = [e for e in events if any(keyword in e.event_type.lower() 
                      for keyword in ['download', 'export', 'transfer', 'copy'])]
        if len(data_events) > 15:
            indicators.append({
                'type': 'potential_data_exfiltration',
                'event_count': len(data_events),
                'description': f'Unusual data access patterns detected: {len(data_events)} events'
            })
        
        return indicators

    def format_report_json(self, stats: SecurityStats) -> str:
        """Format report as JSON"""
        report_dict = asdict(stats)
        # Convert datetime objects to ISO format strings
        report_dict['period_start'] = stats.period_start.isoformat()
        report_dict['period_end'] = stats.period_end.isoformat()
        
        return json.dumps(report_dict, indent=2)

    def format_report_html(self, stats: SecurityStats) -> str:
        """Format report as email-ready HTML"""
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Weekly Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
                .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
                .risk-score { font-size: 2em; font-weight: bold; }
                .risk-low { color: #28a745; }
                .risk-medium { color: #ffc107; }
                .risk-high { color: #dc3545; }
                .breach-indicator { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }
                .severity-critical { color: #dc3545; font-weight: bold; }
                .severity-high { color: #fd7e14; font-weight: bold; }
                .severity-medium { color: #ffc107; font-weight: bold; }
                .severity-low { color: #20c997; }
                .severity-info { color: #6c757d; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Weekly Security Report</h1>
                <p>Period: {{ stats.period_start.strftime('%Y-%m-%d') }} to {{ stats.period_end.strftime('%Y-%m-%d') }}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Alerts</h3>
                        <div class="risk-score">{{ stats.total_alerts }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Risk Score</h3>
                        <div class="risk-score {{ 'risk-low' if stats.risk_score < 30 else 'risk-medium' if stats.risk_score < 70 else 'risk-high' }}">
                            {{ stats.risk_score }}/100
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Breach Indicators</h3>
                        <div class="risk-score {{ 'risk-low' if stats.breach_indicators|length == 0 else 'risk-high' }}">
                            {{ stats.breach_indicators|length }}
                        </div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Alert Breakdown by Severity</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                    {% for severity, count in stats.severity_breakdown.items() %}
                    <tr>
                        <td class="severity-{{ severity.lower() }}">{{ severity }}</td>
                        <td>{{ count }}</td>
                        <td>{{ "%.1f"|format((count / stats.total_alerts * 100) if stats.total_alerts > 0 else 0) }}%</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="section">
                <h2>Alert Sources</h2>
                <table>
                    <tr>
                        <th>Source Type</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                    {% for source, count in stats.source_breakdown.items() %}
                    <tr>
                        <td>{{ source }}</td>
                        <td>{{ count }}</td>
                        <td>{{ "%.1f"|format((count / stats.total_alerts * 100) if stats.total_alerts > 0 else 0) }}%</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            {% if stats.breach_indicators %}
            <div class="section">
                <h2>Breach Analysis</h2>
                <p><strong>⚠️ {{ stats.breach_indicators|length }} potential security concerns identified:</strong></p>
                {% for indicator in stats.breach_indicators %}
                <div class="breach-indicator">
                    <h4>{{ indicator.type.replace('_', ' ').title() }}</h4>
                    <p>{{ indicator.description }}</p>
                    {% if indicator.source_ip %}
                    <p><strong>Source IP:</strong> {{ indicator.source_ip }}</p>
                    {% endif %}
                    {% if indicator.event_count %}
                    <p><strong>Event Count:</strong> {{ indicator.event_count }}</p>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="section">
                <h2>Breach Analysis</h2>
                <p style="color: #28a745;"><strong>✅ No immediate breach indicators detected.</strong></p>
                <p>Continue monitoring for suspicious patterns and maintain security best practices.</p>
            </div>
            {% endif %}

            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {% if stats.risk_score > 70 %}
                    <li><strong>High Priority:</strong> Immediate review of critical and high severity alerts required.</li>
                    <li>Consider implementing additional security controls.</li>
                    {% elif stats.risk_score > 30 %}
                    <li>Review and address medium to high severity alerts.</li>
                    <li>Monitor trends for potential escalation.</li>
                    {% else %}
                    <li>Continue current security posture monitoring.</li>
                    <li>Regular review of security policies and procedures.</li>
                    {% endif %}
                    
                    {% if stats.breach_indicators %}
                    <li><strong>Critical:</strong> Investigate breach indicators immediately.</li>
                    <li>Consider incident response procedures activation.</li>
                    {% endif %}
                    
                    <li>Ensure all security tools are functioning properly.</li>
                    <li>Review user access permissions and authentication logs.</li>
                </ul>
            </div>

            <div style="margin-top: 30px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; text-align: center; color: #6c757d;">
                <p>This report was automatically generated on {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }} UTC</p>
                <p>CyberSec Suite - Automated Security Monitoring</p>
            </div>
        </body>
        </html>
        """
        
        template = Template(template_str)
        return template.render(stats=stats, datetime=datetime)

    def get_custom_report(self, db: Session, start_date: datetime, end_date: datetime) -> SecurityStats:
        """Generate report for custom date range"""
        events = db.query(SecurityEvent).filter(
            and_(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            )
        ).all()
        
        return self._calculate_stats(events, start_date, end_date)

    def get_report_summary(self, stats: SecurityStats) -> Dict:
        """Get a brief summary of the report"""
        risk_level = "LOW"
        if stats.risk_score > 70:
            risk_level = "HIGH"
        elif stats.risk_score > 30:
            risk_level = "MEDIUM"
        
        return {
            "period": f"{stats.period_start.strftime('%Y-%m-%d')} to {stats.period_end.strftime('%Y-%m-%d')}",
            "total_alerts": stats.total_alerts,
            "risk_score": stats.risk_score,
            "risk_level": risk_level,
            "breach_indicators_count": len(stats.breach_indicators),
            "top_severity": max(stats.severity_breakdown, key=stats.severity_breakdown.get) if stats.severity_breakdown else "NONE",
            "top_source": max(stats.source_breakdown, key=stats.source_breakdown.get) if stats.source_breakdown else "NONE"
        }