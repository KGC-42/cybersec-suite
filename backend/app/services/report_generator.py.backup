import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from app.models.security_event import SecurityEvent
from app.database import db
from sqlalchemy import func, and_

class ReportGenerator:
    def __init__(self):
        self.report_data = {}
        self.risk_score = 0
        
    def generate_weekly_report(self) -> Dict[str, Any]:
        """Generate comprehensive weekly security report"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = self._fetch_security_events(start_date, end_date)
        
        # Calculate statistics
        stats = self._calculate_statistics(events)
        
        # Generate breach analysis
        breach_analysis = self._analyze_breaches(events)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(stats, breach_analysis)
        
        # Compile report data
        self.report_data = {
            'report_id': f"weekly_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.utcnow().isoformat(),
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': 7
            },
            'statistics': stats,
            'breach_analysis': breach_analysis,
            'risk_score': risk_score,
            'summary': self._generate_summary(stats, breach_analysis, risk_score),
            'recommendations': self._generate_recommendations(stats, breach_analysis, risk_score)
        }
        
        return self.report_data
    
    def _fetch_security_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from database for date range"""
        return SecurityEvent.query.filter(
            and_(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            )
        ).all()
    
    def _calculate_statistics(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from events"""
        if not events:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_source_type': {},
                'by_category': {},
                'by_day': {},
                'response_times': {},
                'false_positive_rate': 0,
                'resolved_rate': 0
            }
        
        total_alerts = len(events)
        
        # Group by severity
        by_severity = {}
        for event in events:
            severity = event.severity or 'unknown'
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Group by source type
        by_source_type = {}
        for event in events:
            source_type = event.source_type or 'unknown'
            by_source_type[source_type] = by_source_type.get(source_type, 0) + 1
        
        # Group by category
        by_category = {}
        for event in events:
            category = event.event_type or 'uncategorized'
            by_category[category] = by_category.get(category, 0) + 1
        
        # Group by day
        by_day = {}
        for event in events:
            day = event.timestamp.strftime('%Y-%m-%d')
            by_day[day] = by_day.get(day, 0) + 1
        
        # Calculate response times
        response_times = self._calculate_response_times(events)
        
        # Calculate rates
        false_positive_rate = self._calculate_false_positive_rate(events)
        resolved_rate = self._calculate_resolved_rate(events)
        
        return {
            'total_alerts': total_alerts,
            'by_severity': by_severity,
            'by_source_type': by_source_type,
            'by_category': by_category,
            'by_day': by_day,
            'response_times': response_times,
            'false_positive_rate': false_positive_rate,
            'resolved_rate': resolved_rate
        }
    
    def _calculate_response_times(self, events: List[SecurityEvent]) -> Dict[str, float]:
        """Calculate average response times"""
        response_times = []
        for event in events:
            if hasattr(event, 'resolved_at') and event.resolved_at and event.timestamp:
                response_time = (event.resolved_at - event.timestamp).total_seconds() / 3600  # hours
                response_times.append(response_time)
        
        if not response_times:
            return {'average': 0, 'median': 0, 'max': 0, 'min': 0}
        
        response_times.sort()
        return {
            'average': sum(response_times) / len(response_times),
            'median': response_times[len(response_times) // 2],
            'max': max(response_times),
            'min': min(response_times)
        }
    
    def _calculate_false_positive_rate(self, events: List[SecurityEvent]) -> float:
        """Calculate false positive rate"""
        if not events:
            return 0.0
        
        false_positives = sum(1 for event in events 
                            if hasattr(event, 'is_false_positive') and event.is_false_positive)
        return (false_positives / len(events)) * 100
    
    def _calculate_resolved_rate(self, events: List[SecurityEvent]) -> float:
        """Calculate resolution rate"""
        if not events:
            return 0.0
        
        resolved = sum(1 for event in events 
                      if hasattr(event, 'status') and event.status == 'resolved')
        return (resolved / len(events)) * 100
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential security breaches"""
        breach_indicators = []
        critical_events = []
        suspicious_patterns = []
        
        # Identify critical events
        for event in events:
            if event.severity and event.severity.lower() == 'critical':
                critical_events.append({
                    'id': event.id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'source_ip': getattr(event, 'source_ip', 'unknown'),
                    'description': event.description
                })
        
        # Detect suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(events)
        
        # Generate breach indicators
        if critical_events:
            breach_indicators.append("Critical security events detected")
        
        if len(events) > 100:  # High volume of alerts
            breach_indicators.append("High volume of security alerts")
        
        # Check for multiple failed login attempts
        failed_logins = [e for e in events if 'login' in str(e.event_type).lower() and 'fail' in str(e.description).lower()]
        if len(failed_logins) > 50:
            breach_indicators.append("Multiple failed login attempts detected")
        
        return {
            'breach_indicators': breach_indicators,
            'critical_events': critical_events,
            'suspicious_patterns': suspicious_patterns,
            'potential_breach': len(breach_indicators) > 0,
            'breach_confidence': min(len(breach_indicators) * 25, 100)  # Max 100%
        }
    
    def _detect_suspicious_patterns(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in events"""
        patterns = []
        
        # Group events by source IP
        ip_groups = {}
        for event in events:
            source_ip = getattr(event, 'source_ip', None)
            if source_ip:
                if source_ip not in ip_groups:
                    ip_groups[source_ip] = []
                ip_groups[source_ip].append(event)
        
        # Check for suspicious IP activity
        for ip, ip_events in ip_groups.items():
            if len(ip_events) > 20:  # High activity from single IP
                patterns.append({
                    'type': 'high_activity_ip',
                    'description': f'High activity from IP {ip}',
                    'count': len(ip_events),
                    'severity': 'medium'
                })
        
        # Check for time-based patterns (outside business hours)
        night_events = [e for e in events if e.timestamp.hour < 6 or e.timestamp.hour > 22]
        if len(night_events) > len(events) * 0.3:  # More than 30% outside business hours
            patterns.append({
                'type': 'off_hours_activity',
                'description': 'High activity outside business hours',
                'count': len(night_events),
                'severity': 'medium'
            })
        
        return patterns
    
    def _calculate_risk_score(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Base score from total alerts
        total_alerts = stats.get('total_alerts', 0)
        if total_alerts > 100:
            score += 30
        elif total_alerts > 50:
            score += 20
        elif total_alerts > 20:
            score += 10
        
        # Score from severity distribution
        by_severity = stats.get('by_severity', {})
        score += min(by_severity.get('critical', 0) * 5, 25)
        score += min(by_severity.get('high', 0) * 3, 20)
        score += min(by_severity.get('medium', 0) * 1, 15)
        
        # Score from breach analysis
        if breach_analysis.get('potential_breach', False):
            score += breach_analysis.get('breach_confidence', 0) // 4
        
        # Score from response metrics
        resolved_rate = stats.get('resolved_rate', 100)
        if resolved_rate < 50:
            score += 20
        elif resolved_rate < 70:
            score += 10
        
        false_positive_rate = stats.get('false_positive_rate', 0)
        if false_positive_rate > 30:
            score += 10
        
        self.risk_score = min(score, 100)
        return self.risk_score
    
    def _generate_summary(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any], risk_score: int) -> str:
        """Generate executive summary"""
        total_alerts = stats.get('total_alerts', 0)
        critical_count = stats.get('by_severity', {}).get('critical', 0)
        resolved_rate = stats.get('resolved_rate', 0)
        
        risk_level = 'Low'
        if risk_score >= 70:
            risk_level = 'High'
        elif risk_score >= 40:
            risk_level = 'Medium'
        
        summary = f"Weekly Security Report Summary:\n\n"
        summary += f"• Total security alerts: {total_alerts}\n"
        summary += f"• Critical alerts: {critical_count}\n"
        summary += f"• Resolution rate: {resolved_rate:.1f}%\n"
        summary += f"• Overall risk level: {risk_level} (Score: {risk_score}/100)\n"
        
        if breach_analysis.get('potential_breach', False):
            summary += f"• Potential security breach indicators detected\n"
        
        if critical_count > 0:
            summary += f"• Immediate attention required for {critical_count} critical alerts\n"
        
        return summary
    
    def _generate_recommendations(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any], risk_score: int) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Risk-based recommendations
        if risk_score >= 70:
            recommendations.append("Immediate security review recommended due to high risk score")
            recommendations.append("Consider implementing additional monitoring controls")
        
        # Alert volume recommendations
        total_alerts = stats.get('total_alerts', 0)
        if total_alerts > 200:
            recommendations.append("Review alert thresholds to reduce noise")
            recommendations.append("Implement automated alert correlation")
        
        # Resolution rate recommendations
        resolved_rate = stats.get('resolved_rate', 100)
        if resolved_rate < 70:
            recommendations.append("Improve incident response processes to increase resolution rate")
            recommendations.append("Provide additional training to security team")
        
        # False positive recommendations
        false_positive_rate = stats.get('false_positive_rate', 0)
        if false_positive_rate > 20:
            recommendations.append("Fine-tune detection rules to reduce false positives")
            recommendations.append("Implement machine learning for better threat detection")
        
        # Breach analysis recommendations
        if breach_analysis.get('potential_breach', False):
            recommendations.append("Investigate potential breach indicators immediately")
            recommendations.append("Review access controls and network segmentation")
            recommendations.append("Consider engaging external security experts")
        
        # Pattern-based recommendations
        suspicious_patterns = breach_analysis.get('suspicious_patterns', [])
        if any(p['type'] == 'high_activity_ip' for p in suspicious_patterns):
            recommendations.append("Review and potentially block suspicious IP addresses")
        
        if any(p['type'] == 'off_hours_activity' for p in suspicious_patterns):
            recommendations.append("Implement additional monitoring for off-hours activity")
        
        return recommendations
    
    def format_as_json(self) -> str:
        """Format report as JSON string"""
        if not self.report_data:
            self.generate_weekly_report()
        return json.dumps(self.report_data, indent=2, default=str)
    
    def format_as_html(self) -> str:
        """Format report as email-ready HTML"""
        if not self.report_data:
            self.generate_weekly_report()
        
        # Determine risk level color
        risk_score = self.report_data.get('risk_score', 0)
        if risk_score >= 70:
            risk_color = '#dc3545'  # Red
            risk_level = 'High'
        elif risk_score >= 40:
            risk_color = '#fd7e14'  # Orange
            risk_level = 'Medium'
        else:
            risk_color = '#28a745'  # Green
            risk_level = 'Low'
        
        stats = self.report_data.get('statistics', {})
        breach_analysis = self.report_data.get('breach_analysis', {})
        
        html_template = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Weekly Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #007bff; padding-bottom: 20px; }}
        .header h1 {{ color: #007bff; margin: 0; }}
        .risk-score {{ text-align: center; margin: 20px 0; padding: 20px; border-radius: 8px