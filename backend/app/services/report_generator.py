from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.database import SecurityEvent


class ReportGenerator:
    def __init__(self, db_session):
        self.db_session = db_session
    
    def generate_weekly_report(self, user_id):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        events = self.db_session.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= start_date,
            SecurityEvent.timestamp <= end_date
        ).all()
        
        total_events = len(events)
        severity_counts = {}
        event_type_counts = {}
        
        for event in events:
            severity = event.severity
            event_type = event.event_type
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1
            
            if event_type in event_type_counts:
                event_type_counts[event_type] += 1
            else:
                event_type_counts[event_type] = 1
        
        risk_score = self._calculate_risk_score(severity_counts)
        
        date_range = {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d')
        }
        
        return {
            'total_events': total_events,
            'severity_counts': severity_counts,
            'event_type_counts': event_type_counts,
            'risk_score': risk_score,
            'date_range': date_range
        }
    
    def _calculate_risk_score(self, severity_counts):
        if 'critical' in severity_counts:
            return 100
        elif 'high' in severity_counts:
            return 75
        elif 'medium' in severity_counts:
            return 50
        elif 'low' in severity_counts:
            return 25
        else:
            return 0