from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
import json
from ..models import SecurityEvent
from ..database import get_db

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
    
    def generate_weekly_report(self) -> Dict[str, Any]:
        """Generate a comprehensive weekly security report"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = self._fetch_security_events(start_date, end_date)
        
        # Calculate statistics
        stats = self._calculate_statistics(events)
        
        # Generate risk score
        risk_score = self._calculate_risk_score(stats)
        
        # Breach analysis
        breach_analysis = self._analyze_breaches(events)
        
        # Create report structure
        report = {
            'report_id': f"weekly_report_{end_date.strftime('%Y%m%d')}",
            'generated_at': end_date.isoformat(),
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_alerts': stats['total_alerts'],
                'risk_score': risk_score,
                'top_threats': self._get_top_threats(events)
            },
            'statistics': stats,
            'breach_analysis': breach_analysis,
            'recommendations': self._generate_recommendations(stats, risk_score)
        }
        
        return report
    
    def _fetch_security_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events within the specified date range"""
        return self.db.query(SecurityEvent).filter(
            and_(
                SecurityEvent.created_at >= start_date,
                SecurityEvent.created_at <= end_date
            )
        ).all()
    
    def _calculate_statistics(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from security events"""
        total_alerts = len(events)
        
        # Count by severity
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        source_type_counts = {}
        daily_counts = {}
        status_counts = {'open': 0, 'investigating': 0, 'resolved': 0, 'false_positive': 0}
        
        for event in events:
            # Severity distribution
            severity = event.severity.lower() if event.severity else 'unknown'
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Source type distribution
            source_type = event.source_type or 'unknown'
            source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1
            
            # Daily distribution
            day = event.created_at.strftime('%Y-%m-%d')
            daily_counts[day] = daily_counts.get(day, 0) + 1
            
            # Status distribution
            status = event.status.lower() if event.status else 'open'
            if status in status_counts:
                status_counts[status] += 1
        
        return {
            'total_alerts': total_alerts,
            'severity_distribution': severity_counts,
            'source_type_distribution': source_type_counts,
            'daily_distribution': daily_counts,
            'status_distribution': status_counts,
            'resolution_rate': self._calculate_resolution_rate(status_counts),
            'average_daily_alerts': total_alerts / 7 if total_alerts > 0 else 0
        }
    
    def _calculate_resolution_rate(self, status_counts: Dict[str, int]) -> float:
        """Calculate the resolution rate of security events"""
        total_events = sum(status_counts.values())
        if total_events == 0:
            return 0.0
        
        resolved_events = status_counts.get('resolved', 0) + status_counts.get('false_positive', 0)
        return round((resolved_events / total_events) * 100, 2)
    
    def _calculate_risk_score(self, stats: Dict[str, Any]) -> int:
        """Calculate overall risk score based on statistics (0-100)"""
        severity_dist = stats['severity_distribution']
        total_alerts = stats['total_alerts']
        resolution_rate = stats['resolution_rate']
        
        if total_alerts == 0:
            return 0
        
        # Weight severities
        severity_weight = (
            severity_dist['low'] * 1 +
            severity_dist['medium'] * 2 +
            severity_dist['high'] * 3 +
            severity_dist['critical'] * 4
        )
        
        # Normalize by total alerts
        severity_score = min((severity_weight / total_alerts) * 25, 70)
        
        # Factor in resolution rate (lower resolution = higher risk)
        resolution_penalty = max(0, (100 - resolution_rate) * 0.3)
        
        # Factor in volume (more alerts = higher risk)
        volume_score = min(total_alerts * 0.5, 20)
        
        total_risk = severity_score + resolution_penalty + volume_score
        return min(int(total_risk), 100)
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential breaches and security incidents"""
        critical_events = [e for e in events if e.severity and e.severity.lower() == 'critical']
        high_events = [e for e in events if e.severity and e.severity.lower() == 'high']
        
        # Identify potential breaches (critical events or multiple high severity from same source)
        potential_breaches = []
        
        for event in critical_events:
            potential_breaches.append({
                'event_id': event.id,
                'type': 'critical_alert',
                'source': event.source_type,
                'timestamp': event.created_at.isoformat(),
                'description': event.description or 'Critical security event detected',
                'status': event.status
            })
        
        # Group high severity events by source to identify patterns
        source_groups = {}
        for event in high_events:
            source = event.source_type or 'unknown'
            if source not in source_groups:
                source_groups[source] = []
            source_groups[source].append(event)
        
        # Identify sources with multiple high severity events
        for source, source_events in source_groups.items():
            if len(source_events) >= 3:  # 3 or more high severity events from same source
                potential_breaches.append({
                    'type': 'pattern_breach',
                    'source': source,
                    'event_count': len(source_events),
                    'first_event': min(e.created_at for e in source_events).isoformat(),
                    'last_event': max(e.created_at for e in source_events).isoformat(),
                    'description': f'Multiple high severity events detected from {source}'
                })
        
        return {
            'total_potential_breaches': len(potential_breaches),
            'critical_events_count': len(critical_events),
            'high_severity_events_count': len(high_events),
            'potential_breaches': potential_breaches,
            'breach_sources': list(set(breach['source'] for breach in potential_breaches))
        }
    
    def _get_top_threats(self, events: List[SecurityEvent], limit: int = 5) -> List[Dict[str, Any]]:
        """Identify top threats based on frequency and severity"""
        threat_map = {}
        
        for event in events:
            threat_type = event.event_type or 'unknown'
            if threat_type not in threat_map:
                threat_map[threat_type] = {
                    'type': threat_type,
                    'count': 0,
                    'severity_score': 0,
                    'sources': set()
                }
            
            threat_map[threat_type]['count'] += 1
            threat_map[threat_type]['sources'].add(event.source_type or 'unknown')
            
            # Add severity weight
            severity_weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            severity = event.severity.lower() if event.severity else 'low'
            threat_map[threat_type]['severity_score'] += severity_weights.get(severity, 1)
        
        # Convert sources set to list and calculate threat score
        threats = []
        for threat in threat_map.values():
            threat['sources'] = list(threat['sources'])
            threat['threat_score'] = threat['count'] * (threat['severity_score'] / threat['count'])
            threats.append(threat)
        
        # Sort by threat score and return top threats
        return sorted(threats, key=lambda x: x['threat_score'], reverse=True)[:limit]
    
    def _generate_recommendations(self, stats: Dict[str, Any], risk_score: int) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("URGENT: Immediate security review required - Risk score is critically high")
        elif risk_score >= 60:
            recommendations.append("HIGH PRIORITY: Enhanced monitoring and incident response procedures recommended")
        elif risk_score >= 40:
            recommendations.append("MODERATE: Review security policies and increase monitoring frequency")
        else:
            recommendations.append("LOW RISK: Maintain current security posture with regular reviews")
        
        # Resolution rate recommendations
        if stats['resolution_rate'] < 50:
            recommendations.append("Improve incident response times - Resolution rate is below acceptable threshold")
        elif stats['resolution_rate'] < 75:
            recommendations.append("Consider additional resources for incident resolution")
        
        # Volume-based recommendations
        if stats['average_daily_alerts'] > 50:
            recommendations.append("High alert volume detected - Consider tuning detection rules to reduce noise")
        elif stats['average_daily_alerts'] > 20:
            recommendations.append("Moderate alert volume - Review alert prioritization strategies")
        
        # Severity-based recommendations
        critical_count = stats['severity_distribution']['critical']
        high_count = stats['severity_distribution']['high']
        
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical severity events immediately")
        
        if high_count > 10:
            recommendations.append(f"Review and prioritize {high_count} high severity events")
        
        # Source diversity recommendations
        source_count = len(stats['source_type_distribution'])
        if source_count > 10:
            recommendations.append("High source diversity - Consider centralizing security monitoring")
        elif source_count < 3:
            recommendations.append("Limited monitoring sources - Consider expanding security coverage")
        
        return recommendations
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level text based on risk score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MODERATE"
        else:
            return "LOW"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color code for risk level"""
        color_map = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MODERATE": "#ffc107",
            "LOW": "#28a745"
        }
        return color_map.get(risk_level, "#6c757d")
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string"""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as HTML for email distribution"""
        risk_score = report['summary']['risk_score']
        risk_level = self._get_risk_level(risk_score)
        risk_color = self._get_risk_color(risk_level)
        
        # Build severity bar percentages
        total_alerts = report['statistics']['total_alerts']
        if total_alerts > 0:
            severity_dist = report['statistics']['severity_distribution']
            critical_pct = (severity_dist['critical'] / total_alerts) * 100
            high_pct = (severity_dist['high'] / total_alerts) * 100
            medium_pct = (severity_dist['medium'] / total_alerts) * 100
            low_pct = (severity_dist['low'] / total_alerts) * 100
        else:
            critical_pct = high_pct = medium_pct = low_pct = 0
        
        # Build top threats HTML
        top_threats_html = ""
        for threat in report['summary']['top_threats'][:3]:
            top_threats_html += f"""
            <tr>
                <td>{threat['type']}</td>
                <td>{threat['count']}</td>
                <td>{threat.get('threat_score', 0):.1f}</td>
            </tr>"""
        
        # Build recommendations HTML
        recommendations_html = ""
        for rec in report['recommendations']:
            recommendations_html += f"<li>{rec}</li>"
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Weekly Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 20px; }}
        .risk-score {{ font-size: 48px; font-weight: bold; color: {risk_color}; }}
        .risk-level {{ font-size: 24px; color: {risk_color}; margin-top: 10px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 1px solid #e0e0e0; padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .severity-bar {{ display: flex; height: 30px; border-radius: 15px; overflow: hidden; margin: 10px 0; }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; }}
        .severity-low {{ background-color: #28a745; }}
        .recommendations {{ background-color: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; }}
        .recommendations ul {{ margin: 0; padding-left: 20px; }}
        .breach-alert {{ backgroun