from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.database import SecurityEvent

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
        
        # Initialize counters
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        event_type_counts = {}
        
        # Count severities and event types
        for event in events:
            # Count severities
            severity = event.severity.lower() if event.severity else 'low'
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Count event types
            event_type = event.event_type or 'unknown'
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        
        # Create date range dict
        date_range = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }
        
        return {
            'total_events': total_events,
            'severity_counts': severity_counts,
            'event_type_counts': event_type_counts,
            'risk_score': risk_score,
            'date_range': date_range
        }
    
    def _calculate_risk_score(self, severity_counts: dict) -> int:
        if severity_counts['critical'] > 0:
            return 100
        elif severity_counts['high'] > 0:
            return 75
        elif severity_counts['medium'] > 0:
            return 50
        elif severity_counts['low'] > 0:
            return 25
        else:
            return 0