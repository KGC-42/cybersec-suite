from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from ..database import get_db
from ..models.security_event import SecurityEvent

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, db: Session = None):
        self.db = db or next(get_db())
        
    def generate_weekly_report(self, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate a comprehensive weekly security report."""
        if end_date is None:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = self._fetch_events(start_date, end_date)
        
        # Calculate statistics
        stats = self._calculate_stats(events)
        
        # Generate risk score
        risk_score = self._calculate_risk_score(stats, events)
        
        # Perform breach analysis
        breach_analysis = self._analyze_breaches(events)
        
        # Generate summary
        summary = self._generate_summary(stats, risk_score, breach_analysis)
        
        report = {
            'report_id': f"weekly_{end_date.strftime('%Y%m%d')}",
            'generated_at': datetime.utcnow().isoformat(),
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': summary,
            'statistics': stats,
            'risk_score': risk_score,
            'breach_analysis': breach_analysis,
            'total_events': len(events)
        }
        
        return report
    
    def _fetch_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from the specified date range."""
        try:
            events = self.db.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.timestamp <= end_date
                )
            ).all()
            return events
        except Exception as e:
            logger.error(f"Error fetching events: {str(e)}")
            return []
    
    def _calculate_stats(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from security events."""
        total_alerts = len(events)
        
        # Group by severity
        severity_counts = defaultdict(int)
        for event in events:
            severity_counts[event.severity] += 1
        
        # Group by source type
        source_type_counts = defaultdict(int)
        for event in events:
            source_type_counts[event.source_type] += 1
        
        # Group by event type
        event_type_counts = defaultdict(int)
        for event in events:
            event_type_counts[event.event_type] += 1
        
        # Daily distribution
        daily_counts = defaultdict(int)
        for event in events:
            day = event.timestamp.date().isoformat()
            daily_counts[day] += 1
        
        # Top affected systems
        affected_systems = Counter()
        for event in events:
            if hasattr(event, 'affected_system') and event.affected_system:
                affected_systems[event.affected_system] += 1
        
        # Response time analysis
        response_times = []
        resolved_events = [e for e in events if e.status == 'resolved' and e.resolved_at]
        for event in resolved_events:
            response_time = (event.resolved_at - event.timestamp).total_seconds() / 3600  # in hours
            response_times.append(response_time)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'total_alerts': total_alerts,
            'by_severity': dict(severity_counts),
            'by_source_type': dict(source_type_counts),
            'by_event_type': dict(event_type_counts),
            'daily_distribution': dict(daily_counts),
            'top_affected_systems': dict(affected_systems.most_common(10)),
            'response_metrics': {
                'total_resolved': len(resolved_events),
                'avg_response_time_hours': round(avg_response_time, 2),
                'resolution_rate': round(len(resolved_events) / total_alerts * 100, 2) if total_alerts > 0 else 0
            }
        }
    
    def _calculate_risk_score(self, stats: Dict[str, Any], events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate overall risk score based on events and statistics."""
        base_score = 0
        factors = {}
        
        # Severity weighting
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0.5}
        severity_score = 0
        
        for severity, count in stats['by_severity'].items():
            weight = severity_weights.get(severity.lower(), 1)
            severity_score += count * weight
        
        factors['severity_score'] = severity_score
        base_score += min(severity_score, 100)  # Cap at 100
        
        # Volume factor (too many events indicate problems)
        volume_factor = min(stats['total_alerts'] / 10, 20)  # Max 20 points for volume
        factors['volume_factor'] = volume_factor
        base_score += volume_factor
        
        # Unresolved events penalty
        unresolved_events = [e for e in events if e.status != 'resolved']
        unresolved_factor = len(unresolved_events) * 2
        factors['unresolved_factor'] = unresolved_factor
        base_score += unresolved_factor
        
        # Response time factor
        response_time = stats['response_metrics']['avg_response_time_hours']
        response_factor = min(response_time / 2, 15)  # Max 15 points for slow response
        factors['response_factor'] = response_factor
        base_score += response_factor
        
        # Normalize to 0-100 scale
        risk_score = min(base_score, 100)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'score': round(risk_score, 2),
            'level': risk_level,
            'factors': factors,
            'recommendations': self._get_risk_recommendations(risk_level, factors)
        }
    
    def _get_risk_recommendations(self, risk_level: str, factors: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on risk level and factors."""
        recommendations = []
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append("Immediate security team review required")
            recommendations.append("Consider implementing emergency response procedures")
        
        if factors.get('severity_score', 0) > 50:
            recommendations.append("Focus on resolving critical and high severity incidents")
        
        if factors.get('unresolved_factor', 0) > 20:
            recommendations.append("Prioritize resolution of outstanding security events")
        
        if factors.get('response_factor', 0) > 10:
            recommendations.append("Review and optimize incident response procedures")
        
        if factors.get('volume_factor', 0) > 15:
            recommendations.append("Investigate potential security system issues due to high event volume")
        
        if not recommendations:
            recommendations.append("Continue monitoring and maintain current security posture")
        
        return recommendations
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Perform breach analysis on security events."""
        potential_breaches = []
        breach_indicators = []
        
        # Define breach-related event types
        breach_event_types = [
            'data_exfiltration', 'unauthorized_access', 'privilege_escalation',
            'lateral_movement', 'data_breach', 'account_compromise'
        ]
        
        # Identify potential breaches
        for event in events:
            if event.event_type in breach_event_types or event.severity in ['critical', 'high']:
                breach_data = {
                    'event_id': event.id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'description': event.description[:100] + '...' if len(event.description) > 100 else event.description,
                    'source': event.source_ip if hasattr(event, 'source_ip') else 'Unknown',
                    'status': event.status
                }
                potential_breaches.append(breach_data)
        
        # Analyze patterns
        if len(potential_breaches) > 5:
            breach_indicators.append("High volume of critical security events detected")
        
        # Check for multiple events from same source
        source_counts = defaultdict(int)
        for breach in potential_breaches:
            source_counts[breach['source']] += 1
        
        suspicious_sources = [source for source, count in source_counts.items() if count > 3]
        if suspicious_sources:
            breach_indicators.append(f"Multiple incidents from sources: {', '.join(suspicious_sources[:5])}")
        
        # Timeline analysis
        breach_timeline = []
        for breach in sorted(potential_breaches, key=lambda x: x['timestamp']):
            breach_timeline.append({
                'time': breach['timestamp'],
                'event': f"{breach['event_type']} - {breach['severity']}"
            })
        
        return {
            'total_potential_breaches': len(potential_breaches),
            'breach_events': potential_breaches[:10],  # Limit to top 10
            'breach_indicators': breach_indicators,
            'timeline': breach_timeline[:20],  # Limit to 20 events
            'risk_assessment': self._assess_breach_risk(potential_breaches, breach_indicators)
        }
    
    def _assess_breach_risk(self, potential_breaches: List[Dict], indicators: List[str]) -> Dict[str, Any]:
        """Assess the risk of actual security breaches."""
        breach_count = len(potential_breaches)
        indicator_count = len(indicators)
        
        if breach_count > 10 or indicator_count > 3:
            risk_level = 'HIGH'
            confidence = 'High'
        elif breach_count > 5 or indicator_count > 1:
            risk_level = 'MEDIUM'
            confidence = 'Medium'
        elif breach_count > 0:
            risk_level = 'LOW'
            confidence = 'Low'
        else:
            risk_level = 'MINIMAL'
            confidence = 'High'
        
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'breach_probability': min(breach_count * 5 + indicator_count * 10, 100)
        }
    
    def _generate_summary(self, stats: Dict[str, Any], risk_score: Dict[str, Any], breach_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of the security report."""
        key_findings = []
        
        # Total events summary
        total = stats['total_alerts']
        if total > 100:
            key_findings.append(f"High security event volume: {total} events detected")
        elif total > 50:
            key_findings.append(f"Moderate security event volume: {total} events detected")
        else:
            key_findings.append(f"Normal security event volume: {total} events detected")
        
        # Severity breakdown
        critical_count = stats['by_severity'].get('critical', 0)
        high_count = stats['by_severity'].get('high', 0)
        
        if critical_count > 0:
            key_findings.append(f"{critical_count} critical severity events require immediate attention")
        
        if high_count > 0:
            key_findings.append(f"{high_count} high severity events identified")
        
        # Breach analysis summary
        if breach_analysis['total_potential_breaches'] > 0:
            key_findings.append(f"{breach_analysis['total_potential_breaches']} potential security breaches identified")
        
        # Response metrics
        resolution_rate = stats['response_metrics']['resolution_rate']
        if resolution_rate < 70:
            key_findings.append(f"Low resolution rate: {resolution_rate}% of events resolved")
        
        return {
            'overall_risk': risk_score['level'],
            'risk_score': risk_score['score'],
            'key_findings': key_findings,
            'top_concerns': self._identify_top_concerns(stats, breach_analysis),
            'improvements': self._suggest_improvements(stats, risk_score)
        }
    
    def _identify_top_concerns(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any]) -> List[str]:
        """Identify top security concerns from the analysis."""
        concerns = []
        
        if stats['by_severity'].get('critical', 0) > 5:
            concerns.append("Multiple critical security incidents")
        
        if stats['response_metrics']['resolution_rate'] < 50:
            concerns.append("Poor incident resolution rate")
        
        if breach_analysis['risk_assessment']['risk_level'] in ['HIGH', 'MEDIUM']:
            concerns.append("Potential security breach indicators detected")
        
        if stats['response_metrics']['avg_response_time_hours'] > 24:
            concerns.append("Slow incident response times")
        
        # Check for concentration of events
        top_source = max(stats['by_source_type'].items(), key=lambda x: x[1]) if stats['by_source_type'] else None
        if top_source and top_source[1] > stats['total_alerts'] * 0.7:
            concerns.append(f"High concentration of events from {top_source[0]}")
        
        return concerns[:5]  # Limit to top 5 concerns
    
    def _suggest_improvements(self, stats: Dict[str, Any], risk_score: Dict[str, Any]) -> List[str]:
        """Suggest security improvements based on analysis."""
        improvements = []
        
        if stats['response_metrics']['avg_response_time_hours'] > 12:
            improvements.append("Implement automated incident response workflows")
        
        if stats['response_metrics']['resolution_rate'] < 80:
            improvements.append("Enhance incident tracking and resolution processes")
        
        if risk_score['score'] > 60:
            improvements.append("Review and strengthen security monitoring rules")
        
        if len(stats['by_source_type']) < 3:
            improvements.append("Expand security monitoring coverage across more systems")
        
        improvements.append("Regular security awareness training for staff")
        improvements.append("Periodic review of security policies and procedures")
        
        return improvements
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string."""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as email-ready HTML."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Weekly Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: