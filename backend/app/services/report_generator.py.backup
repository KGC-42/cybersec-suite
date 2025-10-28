from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_
from app.models.database import SecurityEvent

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
    
    def generate_weekly_report(self, user_id: int) -> dict:
        # Calculate date range for last 7 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Query security events from last 7 days for the user
        events = self.db.query(SecurityEvent).filter(
            and_(
                SecurityEvent.user_id == user_id,
                SecurityEvent.created_at >= start_date,
                SecurityEvent.created_at <= end_date
            )
        ).all()
        
        # Count total events
        total_events = len(events)
        
        # Count severity levels
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Count event types
        event_type_counts = {}
        
        # Process events
        for event in events:
            # Count severity
            if event.severity.lower() in severity_counts:
                severity_counts[event.severity.lower()] += 1
            
            # Count event types
            event_type = event.event_type
            if event_type in event_type_counts:
                event_type_counts[event_type] += 1
            else:
                event_type_counts[event_type] = 1
        
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