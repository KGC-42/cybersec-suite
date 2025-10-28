"""Security Report Generator Service"""
from datetime import datetime, timedelta
from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.security import SecurityEvent, EventSeverity, EventSource


class ReportGenerator:
    """Generate security reports from events"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def generate_weekly_report(self, user_id: int = None) -> Dict[str, Any]:
        """
        Generate weekly security report
        
        Args:
            user_id: Optional user/org filter
            
        Returns:
            Dict with report data
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Query events
        query = self.db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= start_date,
            SecurityEvent.timestamp <= end_date
        )
        
        if user_id:
            query = query.filter(SecurityEvent.organization_id == user_id)
        
        events = query.all()
        
        # Calculate severity counts
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for event in events:
            if event.severity:
                severity_counts[event.severity.value] += 1
        
        # Calculate source counts
        source_counts = {
            'clamav': 0,
            'phishing': 0,
            'darkweb': 0,
            'suricata': 0,
            'agent': 0
        }
        
        for event in events:
            if event.source:
                source_counts[event.source.value] += 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        
        # Get top events
        top_events = sorted(
            events,
            key=lambda e: self._severity_value(e.severity),
            reverse=True
        )[:10]
        
        return {
            'report_id': f'weekly_{datetime.utcnow().strftime("%Y%m%d")}',
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_events': len(events),
            'severity_counts': severity_counts,
            'source_counts': source_counts,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'top_events': [
                {
                    'id': e.id,
                    'title': e.title,
                    'severity': e.severity.value if e.severity else 'info',
                    'source': e.source.value if e.source else 'agent',
                    'timestamp': e.timestamp.isoformat()
                }
                for e in top_events
            ]
        }
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate risk score 0-100"""
        if severity_counts['critical'] > 0:
            return 100
        elif severity_counts['high'] > 0:
            return 75
        elif severity_counts['medium'] > 0:
            return 50
        elif severity_counts['low'] > 0:
            return 25
        return 0
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level label"""
        if score >= 75:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 25:
            return 'Medium'
        return 'Low'
    
    def _severity_value(self, severity) -> int:
        """Convert severity to numeric value for sorting"""
        values = {
            EventSeverity.CRITICAL: 5,
            EventSeverity.HIGH: 4,
            EventSeverity.MEDIUM: 3,
            EventSeverity.LOW: 2,
            EventSeverity.INFO: 1
        }
        return values.get(severity, 0)