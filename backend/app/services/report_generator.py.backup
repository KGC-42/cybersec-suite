from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models.database import SecurityEvent


class ReportGenerator:
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def generate_weekly_report(self, user_id: int) -> dict:
        # Calculate date range for last 7 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Query security events from last 7 days for the user
        events = self.db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= start_date,
            SecurityEvent.timestamp <= end_date
        ).all()
        
        # Calculate total events
        total_events = len(events)
        
        # Count severity levels
        severity_counts = {}
        for event in events:
            severity = event.severity.lower() if event.severity else 'unknown'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count event types
        event_type_counts = {}
        for event in events:
            event_type = event.event_type if event.event_type else 'unknown'
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Calculate risk score based on severity
        risk_score = self._calculate_risk_score(severity_counts)
        
        # Prepare date range
        date_range = {
            'start': start_date.isoformat(),
            'end': end_date.isoformat()
        }
        
        return {
            'total_events': total_events,
            'severity_counts': severity_counts,
            'event_type_counts': event_type_counts,
            'risk_score': risk_score,
            'date_range': date_range
        }
    
    def _calculate_risk_score(self, severity_counts: dict) -> int:
        if severity_counts.get('critical', 0) > 0:
            return 100
        elif severity_counts.get('high', 0) > 0:
            return 75
        elif severity_counts.get('medium', 0) > 0:
            return 50
        elif severity_counts.get('low', 0) > 0:
            return 25
        else:
            return 0