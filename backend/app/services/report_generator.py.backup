import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
from dataclasses import dataclass

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from models.security_event import SecurityEvent
    from database import SessionLocal
except ImportError:
    # Fallback imports
    import importlib.util
    
    # Load SecurityEvent model
    spec = importlib.util.spec_from_file_location("security_event", 
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "security_event.py"))
    security_event_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security_event_module)
    SecurityEvent = security_event_module.SecurityEvent
    
    # Load database session
    db_spec = importlib.util.spec_from_file_location("database", 
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "database.py"))
    db_module = importlib.util.module_from_spec(db_spec)
    db_spec.loader.exec_module(db_module)
    SessionLocal = db_module.SessionLocal

@dataclass
class SecurityStats:
    total_alerts: int
    by_severity: Dict[str, int]
    by_source_type: Dict[str, int]
    risk_score: float
    high_priority_events: List[Dict]
    breach_indicators: List[Dict]

class ReportGenerator:
    def __init__(self):
        self.db = None
    
    def _get_db_session(self):
        if not self.db:
            self.db = SessionLocal()
        return self.db
    
    def _close_db_session(self):
        if self.db:
            self.db.close()
            self.db = None
    
    def fetch_weekly_security_events(self, end_date: Optional[datetime] = None) -> List[SecurityEvent]:
        """Fetch security events from the last 7 days"""
        if end_date is None:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=7)
        
        db = self._get_db_session()
        try:
            events = db.query(SecurityEvent).filter(
                SecurityEvent.created_at >= start_date,
                SecurityEvent.created_at <= end_date
            ).all()
            return events
        finally:
            self._close_db_session()
    
    def calculate_security_stats(self, events: List[SecurityEvent]) -> SecurityStats:
        """Calculate comprehensive security statistics"""
        total_alerts = len(events)
        
        # Count by severity
        by_severity = {}
        for event in events:
            severity = event.severity or 'unknown'
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Count by source type
        by_source_type = {}
        for event in events:
            source_type = event.source_type or 'unknown'
            by_source_type[source_type] = by_source_type.get(source_type, 0) + 1
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(events, by_severity)
        
        # Identify high priority events
        high_priority_events = [
            {
                'id': event.id,
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip,
                'created_at': event.created_at.isoformat() if event.created_at else None,
                'description': event.description
            }
            for event in events 
            if event.severity in ['critical', 'high']
        ]
        
        # Analyze potential breach indicators
        breach_indicators = self._analyze_breach_indicators(events)
        
        return SecurityStats(
            total_alerts=total_alerts,
            by_severity=by_severity,
            by_source_type=by_source_type,
            risk_score=risk_score,
            high_priority_events=high_priority_events,
            breach_indicators=breach_indicators
        )
    
    def _calculate_risk_score(self, events: List[SecurityEvent], by_severity: Dict[str, int]) -> float:
        """Calculate overall risk score based on events and severity distribution"""
        if not events:
            return 0.0
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1,
            'unknown': 3
        }
        
        total_weighted_score = 0
        max_possible_score = 0
        
        for severity, count in by_severity.items():
            weight = severity_weights.get(severity.lower(), 3)
            total_weighted_score += count * weight
            max_possible_score += count * 10  # Max weight is 10
        
        if max_possible_score == 0:
            return 0.0
        
        base_score = (total_weighted_score / max_possible_score) * 100
        
        # Adjust for volume (more events = higher risk)
        volume_multiplier = min(1.2, 1 + (len(events) / 1000))
        
        return min(100.0, base_score * volume_multiplier)
    
    def _analyze_breach_indicators(self, events: List[SecurityEvent]) -> List[Dict]:
        """Analyze events for potential breach indicators"""
        breach_indicators = []
        
        # Group events by source IP
        ip_events = {}
        for event in events:
            if event.source_ip:
                if event.source_ip not in ip_events:
                    ip_events[event.source_ip] = []
                ip_events[event.source_ip].append(event)
        
        # Look for suspicious patterns
        for ip, ip_event_list in ip_events.items():
            # Multiple high-severity events from same IP
            high_severity_count = sum(1 for e in ip_event_list if e.severity in ['critical', 'high'])
            if high_severity_count >= 3:
                breach_indicators.append({
                    'type': 'multiple_high_severity_from_ip',
                    'source_ip': ip,
                    'count': high_severity_count,
                    'description': f'Multiple high-severity events ({high_severity_count}) from IP {ip}',
                    'risk_level': 'high'
                })
            
            # High volume from single IP
            if len(ip_event_list) >= 20:
                breach_indicators.append({
                    'type': 'high_volume_from_ip',
                    'source_ip': ip,
                    'count': len(ip_event_list),
                    'description': f'High volume of events ({len(ip_event_list)}) from IP {ip}',
                    'risk_level': 'medium'
                })
        
        # Look for authentication failures
        auth_failures = [e for e in events if 'auth' in (e.event_type or '').lower() or 'login' in (e.event_type or '').lower()]
        if len(auth_failures) >= 10:
            breach_indicators.append({
                'type': 'multiple_auth_failures',
                'count': len(auth_failures),
                'description': f'Multiple authentication failures detected ({len(auth_failures)})',
                'risk_level': 'medium'
            })
        
        return breach_indicators
    
    def generate_weekly_report(self, end_date: Optional[datetime] = None) -> Dict:
        """Generate complete weekly security report"""
        if end_date is None:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=7)
        
        # Fetch events and calculate stats
        events = self.fetch_weekly_security_events(end_date)
        stats = self.calculate_security_stats(events)
        
        # Generate summary
        summary = self._generate_summary(stats, start_date, end_date)
        
        report = {
            'report_id': f"weekly_report_{int(end_date.timestamp())}",
            'generated_at': datetime.utcnow().isoformat(),
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': summary,
            'statistics': {
                'total_alerts': stats.total_alerts,
                'by_severity': stats.by_severity,
                'by_source_type': stats.by_source_type,
                'risk_score': round(stats.risk_score, 2)
            },
            'high_priority_events': stats.high_priority_events[:10],  # Limit to top 10
            'breach_analysis': {
                'indicators_found': len(stats.breach_indicators),
                'indicators': stats.breach_indicators,
                'risk_assessment': self._assess_breach_risk(stats.breach_indicators)
            }
        }
        
        return report
    
    def _generate_summary(self, stats: SecurityStats, start_date: datetime, end_date: datetime) -> str:
        """Generate executive summary of the security report"""
        risk_level = self._get_risk_level(stats.risk_score)
        
        summary = f"""Security Report Summary ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})

Total Security Events: {stats.total_alerts}
Overall Risk Score: {stats.risk_score:.1f}/100 ({risk_level})

Severity Breakdown:
"""
        
        for severity, count in sorted(stats.by_severity.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats.total_alerts * 100) if stats.total_alerts > 0 else 0
            summary += f"- {severity.title()}: {count} ({percentage:.1f}%)\n"
        
        summary += f"\nHigh Priority Events: {len(stats.high_priority_events)}\n"
        summary += f"Breach Indicators: {len(stats.breach_indicators)}\n"
        
        if stats.breach_indicators:
            summary += f"\nKey Concerns:\n"
            for indicator in stats.breach_indicators[:3]:  # Top 3 concerns
                summary += f"- {indicator['description']}\n"
        
        return summary
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert numeric risk score to risk level"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _assess_breach_risk(self, breach_indicators: List[Dict]) -> str:
        """Assess overall breach risk based on indicators"""
        if not breach_indicators:
            return "Low - No significant breach indicators detected"
        
        high_risk_count = sum(1 for bi in breach_indicators if bi.get('risk_level') == 'high')
        medium_risk_count = sum(1 for bi in breach_indicators if bi.get('risk_level') == 'medium')
        
        if high_risk_count >= 2:
            return "High - Multiple high-risk indicators detected, immediate investigation recommended"
        elif high_risk_count >= 1:
            return "Medium-High - High-risk indicators present, investigation recommended"
        elif medium_risk_count >= 3:
            return "Medium - Multiple concerning patterns detected"
        elif medium_risk_count >= 1:
            return "Low-Medium - Some concerning patterns, monitoring recommended"
        else:
            return "Low - Minor indicators present"
    
    def format_as_json(self, report: Dict) -> str:
        """Format report as JSON string"""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict) -> str:
        """Format report as email-ready HTML"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Weekly Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
        .header {{ background-color: #1e3a8a; color: white; padding: 20px; text-align: center; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ background-color: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center; min-width: 150px; }}
        .risk-score {{ font-size: 24px; font-weight: bold; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57400; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .minimal {{ color: #4caf50; }}
        .table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .table th, .table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .table th {{ background-color: #f2f2f2; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #1e3a8a; border-bottom: 2px solid #1e3a8a; padding-bottom: 5px; }}
        .alert-item {{ background-color: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 4px solid #ffc107; }}
        .breach-indicator {{ background-color: #f8d7da; padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 4px solid #dc3545; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Weekly Security Report</h1>
        <p>{report['period']['start_date'][:10]} to {report['period']['end_date'][:10]}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <pre>{report['summary']}</pre>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Total Alerts</h3>
            <div class="risk-score">{report['statistics']['total_alerts']}</div>
        </div>
        <div class="stat-box">
            <h3>Risk Score</h3>
            <div class="risk-score {self._get_risk_level(report['statistics']['risk_score']).lower()}">{report['statistics']['risk_score']}/100</div>
        </div>
        <div class="stat-box">
            <h3>High Priority</h3>
            <div class="risk-score">{len(report['high_priority_events'])}</div>
        </div>
        <div class="stat-box">
            <h3>Breach Indicators</h3>
            <div class="risk-score">{report['breach_analysis']['indicators_found']}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Severity Breakdown</h2>
        <table class="table">
            <thead>
                <tr>