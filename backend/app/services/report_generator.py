import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from jinja2 import Template

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.security_event import SecurityEvent
from database import get_db
from sqlalchemy.orm import Session
from sqlalchemy import func, and_


class ReportGenerator:
    def __init__(self, db: Session = None):
        self.db = db or next(get_db())
        self.report_data = {}
        
    def fetch_security_events(self, days: int = 7) -> List[SecurityEvent]:
        """Fetch security events from the last N days"""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        return self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= start_date
        ).all()
    
    def calculate_stats(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate statistics from security events"""
        if not events:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_source_type': {},
                'by_day': {},
                'trend_analysis': {}
            }
        
        # Total alerts
        total_alerts = len(events)
        
        # By severity
        severity_counts = {}
        for event in events:
            severity = event.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # By source type
        source_type_counts = {}
        for event in events:
            source_type = event.source_type
            source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1
        
        # By day
        daily_counts = {}
        for event in events:
            day_key = event.timestamp.strftime('%Y-%m-%d')
            daily_counts[day_key] = daily_counts.get(day_key, 0) + 1
        
        # Trend analysis
        trend_analysis = self._analyze_trends(daily_counts)
        
        return {
            'total_alerts': total_alerts,
            'by_severity': severity_counts,
            'by_source_type': source_type_counts,
            'by_day': daily_counts,
            'trend_analysis': trend_analysis
        }
    
    def _analyze_trends(self, daily_counts: Dict[str, int]) -> Dict[str, Any]:
        """Analyze trends in daily counts"""
        if len(daily_counts) < 2:
            return {'trend': 'insufficient_data', 'percentage_change': 0}
        
        sorted_days = sorted(daily_counts.keys())
        first_half = sorted_days[:len(sorted_days)//2]
        second_half = sorted_days[len(sorted_days)//2:]
        
        first_avg = sum(daily_counts[day] for day in first_half) / len(first_half)
        second_avg = sum(daily_counts[day] for day in second_half) / len(second_half)
        
        if first_avg == 0:
            percentage_change = 100 if second_avg > 0 else 0
        else:
            percentage_change = ((second_avg - first_avg) / first_avg) * 100
        
        trend = 'increasing' if percentage_change > 10 else 'decreasing' if percentage_change < -10 else 'stable'
        
        return {
            'trend': trend,
            'percentage_change': round(percentage_change, 2),
            'first_half_avg': round(first_avg, 2),
            'second_half_avg': round(second_avg, 2)
        }
    
    def calculate_risk_score(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score based on events"""
        base_score = 0
        
        # Severity weights
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0.5
        }
        
        # Calculate weighted severity score
        for severity, count in stats['by_severity'].items():
            weight = severity_weights.get(severity.lower(), 1)
            base_score += count * weight
        
        # Normalize to 0-100 scale
        max_possible_score = stats['total_alerts'] * 10
        if max_possible_score > 0:
            normalized_score = min((base_score / max_possible_score) * 100, 100)
        else:
            normalized_score = 0
        
        # Apply trend multiplier
        trend_multiplier = 1.0
        if stats['trend_analysis']['trend'] == 'increasing':
            trend_multiplier = 1.2
        elif stats['trend_analysis']['trend'] == 'decreasing':
            trend_multiplier = 0.8
        
        final_score = min(normalized_score * trend_multiplier, 100)
        
        # Determine risk level
        if final_score >= 80:
            risk_level = 'CRITICAL'
        elif final_score >= 60:
            risk_level = 'HIGH'
        elif final_score >= 40:
            risk_level = 'MEDIUM'
        elif final_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'score': round(final_score, 2),
            'level': risk_level,
            'base_score': round(base_score, 2),
            'trend_multiplier': trend_multiplier
        }
    
    def generate_breach_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential security breaches"""
        breach_indicators = []
        
        # Look for critical events
        critical_events = [e for e in events if e.severity.lower() == 'critical']
        
        # Look for suspicious patterns
        failed_logins = [e for e in events if 'failed' in e.event_type.lower() and 'login' in e.event_type.lower()]
        malware_events = [e for e in events if 'malware' in e.event_type.lower()]
        intrusion_events = [e for e in events if 'intrusion' in e.event_type.lower()]
        
        # Analyze patterns
        if len(critical_events) > 5:
            breach_indicators.append({
                'type': 'multiple_critical_events',
                'count': len(critical_events),
                'description': f'{len(critical_events)} critical security events detected'
            })
        
        if len(failed_logins) > 10:
            breach_indicators.append({
                'type': 'excessive_failed_logins',
                'count': len(failed_logins),
                'description': f'{len(failed_logins)} failed login attempts detected'
            })
        
        if malware_events:
            breach_indicators.append({
                'type': 'malware_detection',
                'count': len(malware_events),
                'description': f'{len(malware_events)} malware-related events detected'
            })
        
        if intrusion_events:
            breach_indicators.append({
                'type': 'intrusion_attempts',
                'count': len(intrusion_events),
                'description': f'{len(intrusion_events)} intrusion attempts detected'
            })
        
        # Determine breach probability
        breach_probability = 'LOW'
        if len(breach_indicators) >= 3 or any(indicator['count'] > 20 for indicator in breach_indicators):
            breach_probability = 'HIGH'
        elif len(breach_indicators) >= 2:
            breach_probability = 'MEDIUM'
        
        return {
            'breach_probability': breach_probability,
            'indicators': breach_indicators,
            'total_indicators': len(breach_indicators),
            'recommendations': self._get_breach_recommendations(breach_indicators)
        }
    
    def _get_breach_recommendations(self, indicators: List[Dict]) -> List[str]:
        """Generate recommendations based on breach indicators"""
        recommendations = []
        
        for indicator in indicators:
            if indicator['type'] == 'multiple_critical_events':
                recommendations.append('Investigate all critical events immediately')
                recommendations.append('Consider implementing additional monitoring')
            
            elif indicator['type'] == 'excessive_failed_logins':
                recommendations.append('Implement account lockout policies')
                recommendations.append('Review authentication logs for patterns')
            
            elif indicator['type'] == 'malware_detection':
                recommendations.append('Perform full system scan')
                recommendations.append('Update antimalware signatures')
                recommendations.append('Isolate affected systems')
            
            elif indicator['type'] == 'intrusion_attempts':
                recommendations.append('Review firewall rules')
                recommendations.append('Check for unauthorized access')
                recommendations.append('Update intrusion detection signatures')
        
        # Add general recommendations
        if indicators:
            recommendations.extend([
                'Review and update security policies',
                'Conduct security awareness training',
                'Consider engaging incident response team'
            ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_weekly_report(self) -> Dict[str, Any]:
        """Generate complete weekly security report"""
        # Fetch events
        events = self.fetch_security_events(7)
        
        # Calculate statistics
        stats = self.calculate_stats(events)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(stats)
        
        # Generate breach analysis
        breach_analysis = self.generate_breach_analysis(events)
        
        # Create report summary
        summary = self._generate_summary(stats, risk_score, breach_analysis)
        
        self.report_data = {
            'report_date': datetime.utcnow().isoformat(),
            'period': '7 days',
            'summary': summary,
            'statistics': stats,
            'risk_assessment': risk_score,
            'breach_analysis': breach_analysis,
            'total_events_analyzed': len(events)
        }
        
        return self.report_data
    
    def _generate_summary(self, stats: Dict, risk_score: Dict, breach_analysis: Dict) -> str:
        """Generate executive summary"""
        summary_parts = []
        
        # Overview
        summary_parts.append(f"Security Report Summary for the past 7 days:")
        summary_parts.append(f"• Total security events: {stats['total_alerts']}")
        summary_parts.append(f"• Overall risk level: {risk_score['level']} (Score: {risk_score['score']}/100)")
        summary_parts.append(f"• Breach probability: {breach_analysis['breach_probability']}")
        
        # Severity breakdown
        if stats['by_severity']:
            summary_parts.append("\nSecurity Events by Severity:")
            for severity, count in sorted(stats['by_severity'].items(), 
                                        key=lambda x: {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(x[0].lower(), 0), 
                                        reverse=True):
                summary_parts.append(f"• {severity.title()}: {count}")
        
        # Trend analysis
        trend = stats['trend_analysis']
        if trend['trend'] != 'insufficient_data':
            summary_parts.append(f"\nTrend Analysis: Security events are {trend['trend']}")
            if trend['percentage_change'] != 0:
                summary_parts.append(f"• Change from first half to second half of period: {trend['percentage_change']:+.1f}%")
        
        # Key recommendations
        if breach_analysis['indicators']:
            summary_parts.append(f"\nKey Concerns: {len(breach_analysis['indicators'])} security indicators detected")
            summary_parts.append("Immediate attention recommended for breach prevention.")
        
        return '\n'.join(summary_parts)
    
    def format_as_json(self) -> str:
        """Format report as JSON"""
        import json
        return json.dumps(self.report_data, indent=2, default=str)
    
    def format_as_html(self) -> str:
        """Format report as email-ready HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Weekly Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-left: 4px solid #007bff; }
        .risk-high { border-left-color: #dc3545; }
        .risk-critical { border-left-color: #6f42c1; }
        .risk-medium { border-left-color: #fd7e14; }
        .risk-low { border-left-color: #28a745; }
        .stats-grid { display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; flex: 1; min-width: 200px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .breach-analysis { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; }
        .indicator { background-color: #f8d7da; padding: 8px; margin: 5px 0; border-radius: 3px; }
        .recommendations { background-color: #d1ecf1; padding: 15px; margin: 20px 0; }
        .recommendations ul { margin: 10px 0; }
        .footer { text-align: center; color: #6c757d; font-size: 0.9em; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background-color: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Weekly Security Report</h1>
        <p>{{ report_date }}</p>
    </div>

    <div class="summary risk-{{ risk_level.lower() }}">
        <h2>Executive Summary</h2>
        <pre>{{ summary }}</pre>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">{{ total_events }}</div>
            <div>Total Security Events</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ risk_score }}</div>
            <div>Risk Score (0-100)</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ breach_probability }}</div>
            <div>Breach Probability</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ trend }}</div>
            <div>Security Trend</div>
        </div>
    </div>

    <h2>Detailed Statistics</h2>
    
    <h3>Events by Severity</h3>
    <table>
        <thead>
            <tr><th>Severity Level</th><th>Count</th><th>Percentage</th></tr