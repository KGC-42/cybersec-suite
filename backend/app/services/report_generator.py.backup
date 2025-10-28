from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from ..models.security_event import SecurityEvent
from ..database import get_db
import json
from dataclasses import dataclass

@dataclass
class SecurityStats:
    total_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    source_type_breakdown: Dict[str, int]
    daily_breakdown: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    risk_score: float

class ReportGenerator:
    def __init__(self, db: Session = None):
        self.db = db or next(get_db())
    
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
        
        # Create report structure
        report = {
            "report_id": f"weekly_{end_date.strftime('%Y%m%d')}",
            "generated_at": datetime.utcnow().isoformat(),
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "summary": {
                "total_alerts": stats.total_alerts,
                "risk_score": stats.risk_score,
                "risk_level": self._get_risk_level(stats.risk_score),
                "critical_alerts": stats.critical_count,
                "trend": self._calculate_trend(events)
            },
            "statistics": {
                "severity_breakdown": {
                    "critical": stats.critical_count,
                    "high": stats.high_count,
                    "medium": stats.medium_count,
                    "low": stats.low_count,
                    "info": stats.info_count
                },
                "source_type_breakdown": stats.source_type_breakdown,
                "daily_breakdown": stats.daily_breakdown,
                "top_sources": stats.top_sources
            },
            "breach_analysis": breach_analysis,
            "recommendations": self._generate_recommendations(stats, breach_analysis)
        }
        
        return report
    
    def _fetch_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from the specified date range"""
        return self.db.query(SecurityEvent).filter(
            and_(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            )
        ).all()
    
    def _calculate_stats(self, events: List[SecurityEvent]) -> SecurityStats:
        """Calculate comprehensive statistics from events"""
        total_alerts = len(events)
        
        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_type_breakdown = {}
        daily_breakdown = {}
        source_stats = {}
        
        for event in events:
            # Severity counts
            severity = event.severity.lower() if event.severity else "info"
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Source type breakdown
            source_type = event.source_type or "unknown"
            source_type_breakdown[source_type] = source_type_breakdown.get(source_type, 0) + 1
            
            # Daily breakdown
            day = event.timestamp.strftime("%Y-%m-%d")
            daily_breakdown[day] = daily_breakdown.get(day, 0) + 1
            
            # Source statistics
            source = event.source_ip or event.source_host or "unknown"
            if source not in source_stats:
                source_stats[source] = {"count": 0, "severities": set(), "types": set()}
            source_stats[source]["count"] += 1
            source_stats[source]["severities"].add(severity)
            source_stats[source]["types"].add(source_type)
        
        # Top sources
        top_sources = sorted(
            [
                {
                    "source": source,
                    "count": data["count"],
                    "severities": list(data["severities"]),
                    "types": list(data["types"])
                }
                for source, data in source_stats.items()
            ],
            key=lambda x: x["count"],
            reverse=True
        )[:10]
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts, total_alerts)
        
        return SecurityStats(
            total_alerts=total_alerts,
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            source_type_breakdown=source_type_breakdown,
            daily_breakdown=daily_breakdown,
            top_sources=top_sources,
            risk_score=risk_score
        )
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int], total_alerts: int) -> float:
        """Calculate overall risk score based on severity distribution"""
        if total_alerts == 0:
            return 0.0
        
        weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0
        }
        
        weighted_score = sum(
            severity_counts[severity] * weight
            for severity, weight in weights.items()
        )
        
        # Normalize to 0-100 scale
        max_possible_score = total_alerts * weights["critical"]
        risk_score = (weighted_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        return round(risk_score, 2)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _calculate_trend(self, events: List[SecurityEvent]) -> str:
        """Calculate trend compared to previous period"""
        if not events:
            return "stable"
        
        # Split events into two halves of the week
        mid_point = datetime.utcnow() - timedelta(days=3.5)
        
        recent_events = [e for e in events if e.timestamp > mid_point]
        older_events = [e for e in events if e.timestamp <= mid_point]
        
        recent_count = len(recent_events)
        older_count = len(older_events)
        
        if older_count == 0:
            return "increasing" if recent_count > 0 else "stable"
        
        change_ratio = recent_count / older_count
        
        if change_ratio > 1.2:
            return "increasing"
        elif change_ratio < 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def _analyze_breaches(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze potential security breaches"""
        breach_indicators = []
        suspicious_patterns = []
        
        # Group events by source
        source_events = {}
        for event in events:
            source = event.source_ip or event.source_host or "unknown"
            if source not in source_events:
                source_events[source] = []
            source_events[source].append(event)
        
        # Analyze patterns
        for source, source_event_list in source_events.items():
            if len(source_event_list) > 10:  # High frequency from single source
                critical_events = [e for e in source_event_list if e.severity and e.severity.lower() == "critical"]
                
                if critical_events:
                    breach_indicators.append({
                        "source": source,
                        "type": "potential_breach",
                        "description": f"Multiple critical events from {source}",
                        "event_count": len(source_event_list),
                        "critical_count": len(critical_events),
                        "first_seen": min(e.timestamp for e in source_event_list).isoformat(),
                        "last_seen": max(e.timestamp for e in source_event_list).isoformat()
                    })
                
                if len(source_event_list) > 50:
                    suspicious_patterns.append({
                        "source": source,
                        "type": "high_frequency_activity",
                        "description": f"Unusually high activity from {source}",
                        "event_count": len(source_event_list)
                    })
        
        # Look for authentication failures
        auth_failures = [e for e in events if e.event_type and "auth" in e.event_type.lower()]
        if len(auth_failures) > 20:
            breach_indicators.append({
                "type": "authentication_anomaly",
                "description": "High number of authentication-related events",
                "event_count": len(auth_failures)
            })
        
        return {
            "breach_indicators": breach_indicators,
            "suspicious_patterns": suspicious_patterns,
            "total_indicators": len(breach_indicators),
            "breach_risk_level": "High" if len(breach_indicators) > 2 else "Medium" if len(breach_indicators) > 0 else "Low"
        }
    
    def _generate_recommendations(self, stats: SecurityStats, breach_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if stats.critical_count > 0:
            recommendations.append("Immediate attention required: Address all critical security alerts")
        
        if stats.risk_score > 70:
            recommendations.append("Implement additional security monitoring and response procedures")
        
        if breach_analysis["total_indicators"] > 0:
            recommendations.append("Investigate potential security breach indicators immediately")
        
        if stats.total_alerts > 100:
            recommendations.append("Consider implementing alert filtering to reduce noise")
        
        # Source-based recommendations
        top_source_count = stats.top_sources[0]["count"] if stats.top_sources else 0
        if top_source_count > 20:
            recommendations.append(f"Investigate high-activity source: {stats.top_sources[0]['source']}")
        
        if not recommendations:
            recommendations.append("Continue monitoring current security posture")
        
        return recommendations
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string"""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as HTML for email"""
        summary = report["summary"]
        stats = report["statistics"]
        breach_analysis = report["breach_analysis"]
        
        # Risk level color mapping
        risk_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Minimal": "#6c757d"
        }
        
        risk_color = risk_colors.get(summary["risk_level"], "#6c757d")
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Weekly Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ background-color: #fff; border: 1px solid #dee2e6; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .risk-score {{ font-size: 2em; font-weight: bold; color: {risk_color}; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }}
        .stat-card {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }}
        .stat-number {{ font-size: 1.5em; font-weight: bold; color: #007bff; }}
        .breach-alert {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .recommendations {{ background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Weekly Security Report</h1>
        <p><strong>Period:</strong> {report['period']['start_date'][:10]} to {report['period']['end_date'][:10]}</p>
        <p><strong>Generated:</strong> {report['generated_at'][:19]} UTC</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{summary['total_alerts']}</div>
                <div>Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="risk-score">{summary['risk_score']}</div>
                <div>Risk Score ({summary['risk_level']})</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical">{summary['critical_alerts']}</div>
                <div>Critical Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['trend'].title()}</div>
                <div>Trend</div>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <h2>Severity Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""
        
        total = summary['total_alerts'] or 1
        for severity, count in stats['severity_breakdown'].items():
            percentage = (count / total) * 100
            severity_class = severity if severity in ['critical', 'high', 'medium'] else ''
            html_template += f