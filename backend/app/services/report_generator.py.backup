from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy import and_, func
from app.models.security_event import SecurityEvent
from app.database import SessionLocal
import json

class ReportGenerator:
    def __init__(self):
        self.db = SessionLocal()
    
    def __del__(self):
        if hasattr(self, 'db'):
            self.db.close()
    
    def generate_weekly_report(self, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate comprehensive weekly security report"""
        if end_date is None:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = self._fetch_events(start_date, end_date)
        
        # Calculate statistics
        stats = self._calculate_stats(events)
        
        # Generate breach analysis
        breach_analysis = self._analyze_breaches(events)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(stats, breach_analysis)
        
        # Generate summary
        summary = self._generate_summary(stats, risk_score, breach_analysis)
        
        report = {
            'report_id': f"weekly_{end_date.strftime('%Y%m%d')}",
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'generated_at': datetime.utcnow().isoformat(),
            'summary': summary,
            'risk_score': risk_score,
            'statistics': stats,
            'breach_analysis': breach_analysis,
            'total_events': len(events)
        }
        
        return report
    
    def _fetch_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from database for given date range"""
        try:
            events = self.db.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.timestamp >= start_date,
                    SecurityEvent.timestamp <= end_date
                )
            ).all()
            return events
        except Exception as e:
            print(f"Error fetching events: {e}")
            return []
    
    def _calculate_stats(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from events"""
        if not events:
            return {
                'total_alerts': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'by_source_type': {},
                'by_event_type': {},
                'daily_breakdown': {},
                'top_sources': [],
                'trend_analysis': {}
            }
        
        # Total alerts
        total_alerts = len(events)
        
        # By severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for event in events:
            severity = event.severity.lower() if event.severity else 'info'
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # By source type
        source_type_counts = {}
        for event in events:
            source_type = event.source_type or 'unknown'
            source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1
        
        # By event type
        event_type_counts = {}
        for event in events:
            event_type = event.event_type or 'unknown'
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Daily breakdown
        daily_breakdown = {}
        for event in events:
            day = event.timestamp.date().isoformat()
            daily_breakdown[day] = daily_breakdown.get(day, 0) + 1
        
        # Top sources
        source_counts = {}
        for event in events:
            source = event.source_ip or 'unknown'
            source_counts[source] = source_counts.get(source, 0) + 1
        
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Trend analysis
        trend_analysis = self._calculate_trend_analysis(events)
        
        return {
            'total_alerts': total_alerts,
            'by_severity': severity_counts,
            'by_source_type': source_type_counts,
            'by_event_type': event_type_counts,
            'daily_breakdown': daily_breakdown,
            'top_sources': top_sources,
            'trend_analysis': trend_analysis
        }
    
    def _calculate_trend_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate trend analysis for events"""
        if not events:
            return {'trend': 'stable', 'percentage_change': 0}
        
        # Split events into first and second half of the week
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        midpoint = len(sorted_events) // 2
        
        first_half = sorted_events[:midpoint] if midpoint > 0 else []
        second_half = sorted_events[midpoint:] if midpoint > 0 else sorted_events
        
        first_half_count = len(first_half)
        second_half_count = len(second_half)
        
        if first_half_count == 0:
            percentage_change = 100 if second_half_count > 0 else 0
        else:
            percentage_change = ((second_half_count - first_half_count) / first_half_count) * 100
        
        if percentage_change > 20:
            trend = 'increasing'
        elif percentage_change < -20:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'percentage_change': round(percentage_change, 2),
            'first_half_count': first_half_count,
            'second_half_count': second_half_count
        }
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential security breaches"""
        breach_indicators = []
        potential_breaches = 0
        critical_events = []
        
        for event in events:
            # Check for breach indicators
            if event.severity and event.severity.lower() == 'critical':
                critical_events.append({
                    'event_type': event.event_type,
                    'source_ip': event.source_ip,
                    'timestamp': event.timestamp.isoformat(),
                    'description': event.description
                })
                potential_breaches += 1
            
            # Check for common breach patterns
            if event.event_type and any(indicator in event.event_type.lower() for indicator in 
                                      ['breach', 'intrusion', 'unauthorized', 'malware', 'ransomware']):
                breach_indicators.append({
                    'type': event.event_type,
                    'source': event.source_ip,
                    'timestamp': event.timestamp.isoformat()
                })
        
        # Analyze attack patterns
        attack_patterns = self._identify_attack_patterns(events)
        
        # Risk assessment
        risk_level = 'low'
        if potential_breaches > 5:
            risk_level = 'critical'
        elif potential_breaches > 2:
            risk_level = 'high'
        elif potential_breaches > 0:
            risk_level = 'medium'
        
        return {
            'potential_breaches': potential_breaches,
            'risk_level': risk_level,
            'breach_indicators': breach_indicators[:10],  # Limit to top 10
            'critical_events': critical_events[:10],
            'attack_patterns': attack_patterns,
            'recommendations': self._generate_breach_recommendations(risk_level, potential_breaches)
        }
    
    def _identify_attack_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Identify common attack patterns from events"""
        patterns = {
            'brute_force': 0,
            'ddos': 0,
            'malware': 0,
            'phishing': 0,
            'suspicious_login': 0
        }
        
        for event in events:
            event_type = (event.event_type or '').lower()
            description = (event.description or '').lower()
            
            if 'brute' in event_type or 'brute' in description:
                patterns['brute_force'] += 1
            elif 'ddos' in event_type or 'ddos' in description:
                patterns['ddos'] += 1
            elif 'malware' in event_type or 'virus' in description:
                patterns['malware'] += 1
            elif 'phish' in event_type or 'phish' in description:
                patterns['phishing'] += 1
            elif 'login' in event_type and 'fail' in description:
                patterns['suspicious_login'] += 1
        
        return patterns
    
    def _generate_breach_recommendations(self, risk_level: str, breach_count: int) -> List[str]:
        """Generate recommendations based on breach analysis"""
        recommendations = []
        
        if risk_level == 'critical':
            recommendations.extend([
                "Immediate incident response required",
                "Review and strengthen access controls",
                "Consider engaging external security experts",
                "Implement additional monitoring on critical systems"
            ])
        elif risk_level == 'high':
            recommendations.extend([
                "Increase monitoring frequency",
                "Review security policies and procedures",
                "Update threat detection rules",
                "Conduct security awareness training"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Monitor trends closely",
                "Review recent security events",
                "Update security configurations as needed"
            ])
        else:
            recommendations.extend([
                "Continue regular monitoring",
                "Maintain current security posture",
                "Regular security assessments recommended"
            ])
        
        return recommendations
    
    def _calculate_risk_score(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score (0-100)"""
        base_score = 0
        
        # Severity-based scoring
        severity_weights = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2, 'info': 1}
        for severity, count in stats['by_severity'].items():
            base_score += count * severity_weights.get(severity, 1)
        
        # Breach indicators impact
        base_score += breach_analysis['potential_breaches'] * 15
        
        # Trend impact
        trend_analysis = stats.get('trend_analysis', {})
        if trend_analysis.get('trend') == 'increasing':
            base_score *= 1.2
        elif trend_analysis.get('trend') == 'decreasing':
            base_score *= 0.8
        
        # Normalize to 0-100 scale
        risk_score = min(100, max(0, base_score))
        
        # Determine risk category
        if risk_score >= 80:
            risk_category = 'critical'
        elif risk_score >= 60:
            risk_category = 'high'
        elif risk_score >= 40:
            risk_category = 'medium'
        elif risk_score >= 20:
            risk_category = 'low'
        else:
            risk_category = 'minimal'
        
        return {
            'score': round(risk_score, 2),
            'category': risk_category,
            'factors': {
                'severity_events': sum(stats['by_severity'].values()),
                'potential_breaches': breach_analysis['potential_breaches'],
                'trend_factor': trend_analysis.get('trend', 'stable')
            }
        }
    
    def _generate_summary(self, stats: Dict[str, Any], risk_score: Dict[str, Any], breach_analysis: Dict[str, Any]) -> str:
        """Generate executive summary"""
        total_events = stats['total_alerts']
        risk_category = risk_score['category']
        potential_breaches = breach_analysis['potential_breaches']
        
        summary = f"""Weekly Security Report Summary:
        
During the past 7 days, our security monitoring systems detected {total_events} security events. 
The overall risk level is assessed as {risk_category.upper()} with a risk score of {risk_score['score']}/100.

Key Findings:
- Critical Events: {stats['by_severity']['critical']}
- High Severity Events: {stats['by_severity']['high']}
- Medium Severity Events: {stats['by_severity']['medium']}
- Potential Breach Indicators: {potential_breaches}

The security posture shows a {stats['trend_analysis']['trend']} trend compared to the previous period.
{f"Immediate attention required for {potential_breaches} potential security incidents." if potential_breaches > 0 else "No critical security incidents detected."}

Top Recommendations:
{chr(10).join(['- ' + rec for rec in breach_analysis['recommendations'][:3]])}
"""
        
        return summary
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string"""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as HTML for email"""
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Weekly Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }}
        .risk-score {{ font-size: 24px; font-weight: bold; text-align: center; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .critical {{ background-color: #e74c3c; color: white; }}
        .high {{ background-color: #e67e22; color: white; }}
        .medium {{ background-color: #f39c12; color: white; }}
        .low {{ background-color: #27ae60; color: white; }}
        .minimal {{ background-color: #95a5a6; color: white; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ font-size: 14px; color: #7f8c8d; }}
        .section {{ margin: 30px 0; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}