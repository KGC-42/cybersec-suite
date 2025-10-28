from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.security_event import SecurityEvent
import json
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
    
    def generate_weekly_report(self) -> Dict[str, Any]:
        """Generate comprehensive weekly security report"""
        try:
            # Calculate date range for last 7 days
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)
            
            # Fetch security events from last 7 days
            events = self._fetch_weekly_events(start_date, end_date)
            
            # Calculate statistics
            stats = self._calculate_statistics(events)
            
            # Generate breach analysis
            breach_analysis = self._analyze_breaches(events)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(stats, breach_analysis)
            
            # Generate summary
            summary = self._generate_summary(stats, risk_score)
            
            report = {
                'report_id': f"weekly_{end_date.strftime('%Y%m%d')}",
                'generated_at': end_date.isoformat(),
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'summary': summary,
                'statistics': stats,
                'breach_analysis': breach_analysis,
                'risk_score': risk_score,
                'total_events': len(events)
            }
            
            logger.info(f"Weekly report generated successfully with {len(events)} events")
            return report
            
        except Exception as e:
            logger.error(f"Error generating weekly report: {str(e)}")
            raise
    
    def _fetch_weekly_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from the last 7 days"""
        try:
            events = self.db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            ).all()
            
            return events
        except Exception as e:
            logger.error(f"Error fetching weekly events: {str(e)}")
            return []
    
    def _calculate_statistics(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from security events"""
        if not events:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_source_type': {},
                'by_event_type': {},
                'by_day': {},
                'trends': {}
            }
        
        stats = {
            'total_alerts': len(events),
            'by_severity': {},
            'by_source_type': {},
            'by_event_type': {},
            'by_day': {},
            'trends': {}
        }
        
        # Count by severity
        severity_counts = {}
        for event in events:
            severity = event.severity or 'unknown'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        stats['by_severity'] = severity_counts
        
        # Count by source type
        source_counts = {}
        for event in events:
            source = event.source_type or 'unknown'
            source_counts[source] = source_counts.get(source, 0) + 1
        stats['by_source_type'] = source_counts
        
        # Count by event type
        event_type_counts = {}
        for event in events:
            event_type = event.event_type or 'unknown'
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        stats['by_event_type'] = event_type_counts
        
        # Count by day
        daily_counts = {}
        for event in events:
            day = event.timestamp.strftime('%Y-%m-%d')
            daily_counts[day] = daily_counts.get(day, 0) + 1
        stats['by_day'] = daily_counts
        
        # Calculate trends
        stats['trends'] = self._calculate_trends(events)
        
        return stats
    
    def _calculate_trends(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate security trends from events"""
        if not events:
            return {}
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # Split into first and second half of the week
        mid_point = len(sorted_events) // 2
        first_half = sorted_events[:mid_point]
        second_half = sorted_events[mid_point:]
        
        trends = {
            'weekly_change': 0,
            'severity_trends': {},
            'most_active_day': '',
            'peak_hours': []
        }
        
        # Calculate weekly change
        if len(first_half) > 0:
            change = ((len(second_half) - len(first_half)) / len(first_half)) * 100
            trends['weekly_change'] = round(change, 2)
        
        # Find most active day
        daily_counts = {}
        for event in events:
            day = event.timestamp.strftime('%A')
            daily_counts[day] = daily_counts.get(day, 0) + 1
        
        if daily_counts:
            trends['most_active_day'] = max(daily_counts, key=daily_counts.get)
        
        # Find peak hours
        hourly_counts = {}
        for event in events:
            hour = event.timestamp.hour
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        
        if hourly_counts:
            # Get top 3 peak hours
            sorted_hours = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)
            trends['peak_hours'] = [hour for hour, count in sorted_hours[:3]]
        
        return trends
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential security breaches from events"""
        breach_analysis = {
            'potential_breaches': 0,
            'breach_indicators': [],
            'affected_sources': [],
            'critical_events': [],
            'recommendations': []
        }
        
        critical_events = []
        breach_indicators = []
        affected_sources = set()
        
        for event in events:
            # Identify critical events
            if event.severity and event.severity.lower() in ['critical', 'high']:
                critical_events.append({
                    'id': event.id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'description': event.description[:100] + '...' if event.description and len(event.description) > 100 else event.description
                })
                affected_sources.add(event.source_type or 'unknown')
            
            # Identify breach indicators
            if event.event_type:
                if any(indicator in event.event_type.lower() for indicator in [
                    'unauthorized', 'breach', 'intrusion', 'malware', 'attack'
                ]):
                    breach_indicators.append(event.event_type)
            
            if event.description:
                if any(indicator in event.description.lower() for indicator in [
                    'data exfiltration', 'privilege escalation', 'lateral movement'
                ]):
                    breach_indicators.append(event.event_type or 'unknown')
        
        breach_analysis['potential_breaches'] = len(set(breach_indicators))
        breach_analysis['breach_indicators'] = list(set(breach_indicators))
        breach_analysis['affected_sources'] = list(affected_sources)
        breach_analysis['critical_events'] = critical_events[-10:]  # Last 10 critical events
        
        # Generate recommendations
        recommendations = []
        if len(critical_events) > 10:
            recommendations.append("High number of critical events detected. Immediate investigation recommended.")
        
        if 'malware' in str(breach_indicators).lower():
            recommendations.append("Malware activity detected. Run comprehensive system scans.")
        
        if len(affected_sources) > 5:
            recommendations.append("Multiple sources affected. Review security policies across all systems.")
        
        breach_analysis['recommendations'] = recommendations
        
        return breach_analysis
    
    def _calculate_risk_score(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score based on statistics and breach analysis"""
        base_score = 0
        risk_factors = []
        
        # Factor in severity distribution
        severity_score = 0
        if stats['by_severity']:
            critical_count = stats['by_severity'].get('critical', 0)
            high_count = stats['by_severity'].get('high', 0)
            medium_count = stats['by_severity'].get('medium', 0)
            
            severity_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)
            
            if critical_count > 0:
                risk_factors.append(f"{critical_count} critical severity events")
            if high_count > 5:
                risk_factors.append(f"{high_count} high severity events")
        
        # Factor in potential breaches
        breach_score = breach_analysis['potential_breaches'] * 15
        if breach_analysis['potential_breaches'] > 0:
            risk_factors.append(f"{breach_analysis['potential_breaches']} potential breach indicators")
        
        # Factor in event volume
        volume_score = min(stats['total_alerts'] / 10, 20)  # Cap at 20 points
        if stats['total_alerts'] > 100:
            risk_factors.append(f"High event volume: {stats['total_alerts']} events")
        
        # Calculate final score
        base_score = severity_score + breach_score + volume_score
        final_score = min(base_score, 100)  # Cap at 100
        
        # Determine risk level
        if final_score >= 80:
            risk_level = "CRITICAL"
        elif final_score >= 60:
            risk_level = "HIGH"
        elif final_score >= 40:
            risk_level = "MEDIUM"
        elif final_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'score': round(final_score, 2),
            'level': risk_level,
            'factors': risk_factors,
            'breakdown': {
                'severity_score': severity_score,
                'breach_score': breach_score,
                'volume_score': round(volume_score, 2)
            }
        }
    
    def _generate_summary(self, stats: Dict[str, Any], risk_score: Dict[str, Any]) -> str:
        """Generate executive summary of the security report"""
        total_events = stats['total_alerts']
        risk_level = risk_score['level']
        risk_value = risk_score['score']
        
        # Get top severity and source
        top_severity = max(stats['by_severity'].items(), key=lambda x: x[1])[0] if stats['by_severity'] else 'N/A'
        top_source = max(stats['by_source_type'].items(), key=lambda x: x[1])[0] if stats['by_source_type'] else 'N/A'
        
        summary = f"""
        Weekly Security Report Summary:
        
        During the past 7 days, our security monitoring systems recorded {total_events} security events.
        The overall risk assessment indicates a {risk_level} risk level with a score of {risk_value}/100.
        
        Key Findings:
        • Most common severity level: {top_severity}
        • Primary source of events: {top_source}
        • Risk factors identified: {len(risk_score['factors'])}
        
        {f"IMMEDIATE ATTENTION REQUIRED: {', '.join(risk_score['factors'][:3])}" if risk_level in ['CRITICAL', 'HIGH'] else "Security posture within acceptable parameters."}
        """
        
        return summary.strip()
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string"""
        try:
            return json.dumps(report, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error formatting report as JSON: {str(e)}")
            return "{}"
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as email-ready HTML"""
        try:
            risk_color = self._get_risk_color(report['risk_score']['level'])
            
            # Format statistics tables
            severity_table = self._create_html_table(report['statistics']['by_severity'], "Severity", "Count")
            source_table = self._create_html_table(report['statistics']['by_source_type'], "Source Type", "Count")
            
            # Format critical events
            critical_events_html = ""
            if report['breach_analysis']['critical_events']:
                critical_events_html = "<h3>Recent Critical Events</h3><ul>"
                for event in report['breach_analysis']['critical_events'][:5]:
                    critical_events_html += f"<li><strong>{event['timestamp']}</strong> - {event['event_type']} ({event['severity']})</li>"
                critical_events_html += "</ul>"
            
            html_template = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
                    .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                    .risk-score {{ font-size: 24px; font-weight: bold; color: {risk_color}; }}
                    .section {{ margin-bottom: 30px; }}
                    .stats-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
                    table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
                    th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f5f5f5; font-weight: bold; }}
                    .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; }}
                    .recommendations {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; }}
                    ul {{ margin: 10px 0; }}
                    li {{ margin-bottom: 5px; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Weekly Security Report</h1>
                    <p><strong>Report Period:</strong> {report['period']['start_date'][:10]} to {report['period']['end_date'][:10]}</p>
                    <p><strong>Generated:</strong> {report['generated_at'][:19].replace('T', ' ')}</p>
                    <p class="risk-score">Risk Level: {report['risk_score']['level']} ({report['risk_score']['score']}/100)</p>
                </div>
                
                <div class="section">
                    <h2>Executive Summary</h2>
                    <div class="summary">
                        <pre>{report['summary']