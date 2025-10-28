from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import Counter
import json
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.security_event import SecurityEvent
from app.core.database import get_db
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
    
    def generate_weekly_report(self, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate a comprehensive weekly security report."""
        if end_date is None:
            end_date = datetime.utcnow()
        
        start_date = end_date - timedelta(days=7)
        
        # Fetch security events from last 7 days
        events = self._fetch_security_events(start_date, end_date)
        
        # Calculate statistics
        stats = self._calculate_statistics(events)
        
        # Generate risk score
        risk_score = self._calculate_risk_score(stats)
        
        # Generate breach analysis
        breach_analysis = self._generate_breach_analysis(events)
        
        # Generate executive summary
        summary = self._generate_summary(stats, risk_score)
        
        report = {
            "report_id": f"weekly_{end_date.strftime('%Y%m%d')}",
            "generated_at": datetime.utcnow().isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": summary,
            "statistics": stats,
            "risk_score": risk_score,
            "breach_analysis": breach_analysis,
            "recommendations": self._generate_recommendations(stats, breach_analysis)
        }
        
        logger.info(f"Generated weekly report for period {start_date} to {end_date}")
        return report
    
    def _fetch_security_events(self, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """Fetch security events from the specified date range."""
        try:
            events = (
                self.db.query(SecurityEvent)
                .filter(SecurityEvent.timestamp >= start_date)
                .filter(SecurityEvent.timestamp <= end_date)
                .all()
            )
            return events
        except Exception as e:
            logger.error(f"Error fetching security events: {str(e)}")
            return []
    
    def _calculate_statistics(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from security events."""
        total_alerts = len(events)
        
        if total_alerts == 0:
            return {
                "total_alerts": 0,
                "by_severity": {},
                "by_source_type": {},
                "by_category": {},
                "by_day": {},
                "most_targeted_assets": [],
                "attack_patterns": []
            }
        
        # Group by severity
        severity_counts = Counter(event.severity for event in events)
        
        # Group by source type
        source_type_counts = Counter(event.source_type for event in events)
        
        # Group by category
        category_counts = Counter(event.category for event in events)
        
        # Group by day
        day_counts = Counter(event.timestamp.date() for event in events)
        day_counts_str = {str(k): v for k, v in day_counts.items()}
        
        # Most targeted assets
        asset_counts = Counter()
        for event in events:
            if hasattr(event, 'affected_asset') and event.affected_asset:
                asset_counts[event.affected_asset] += 1
        most_targeted_assets = asset_counts.most_common(10)
        
        # Attack patterns analysis
        attack_patterns = self._analyze_attack_patterns(events)
        
        return {
            "total_alerts": total_alerts,
            "by_severity": dict(severity_counts),
            "by_source_type": dict(source_type_counts),
            "by_category": dict(category_counts),
            "by_day": day_counts_str,
            "most_targeted_assets": most_targeted_assets,
            "attack_patterns": attack_patterns
        }
    
    def _analyze_attack_patterns(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Analyze attack patterns from security events."""
        patterns = []
        
        # Group events by source IP
        ip_events = {}
        for event in events:
            if hasattr(event, 'source_ip') and event.source_ip:
                if event.source_ip not in ip_events:
                    ip_events[event.source_ip] = []
                ip_events[event.source_ip].append(event)
        
        # Identify suspicious patterns
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 5:  # Multiple events from same IP
                pattern = {
                    "type": "repeated_source",
                    "source_ip": ip,
                    "event_count": len(ip_event_list),
                    "severity_distribution": dict(Counter(e.severity for e in ip_event_list)),
                    "time_span": self._calculate_time_span(ip_event_list)
                }
                patterns.append(pattern)
        
        # Look for brute force patterns
        brute_force_events = [e for e in events if 'login' in e.category.lower() or 'auth' in e.category.lower()]
        if len(brute_force_events) > 10:
            patterns.append({
                "type": "potential_brute_force",
                "event_count": len(brute_force_events),
                "unique_sources": len(set(getattr(e, 'source_ip', 'unknown') for e in brute_force_events))
            })
        
        return patterns
    
    def _calculate_time_span(self, events: List[SecurityEvent]) -> Dict[str, str]:
        """Calculate time span for a list of events."""
        timestamps = [e.timestamp for e in events]
        return {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_hours": str((max(timestamps) - min(timestamps)).total_seconds() / 3600)
        }
    
    def _calculate_risk_score(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score based on statistics."""
        if stats["total_alerts"] == 0:
            return {"score": 0, "level": "LOW", "factors": []}
        
        score = 0
        factors = []
        
        # Base score from total alerts
        total_alerts = stats["total_alerts"]
        if total_alerts > 100:
            score += 30
            factors.append("High volume of security alerts")
        elif total_alerts > 50:
            score += 20
            factors.append("Moderate volume of security alerts")
        elif total_alerts > 10:
            score += 10
            factors.append("Low volume of security alerts")
        
        # Score from severity distribution
        severity_counts = stats["by_severity"]
        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)
        
        if critical_count > 0:
            score += critical_count * 10
            factors.append(f"{critical_count} critical severity alerts")
        
        if high_count > 5:
            score += high_count * 5
            factors.append(f"{high_count} high severity alerts")
        
        # Score from attack patterns
        attack_patterns = stats.get("attack_patterns", [])
        if len(attack_patterns) > 0:
            score += len(attack_patterns) * 15
            factors.append(f"{len(attack_patterns)} suspicious attack patterns detected")
        
        # Determine risk level
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        elif score >= 20:
            level = "LOW"
        else:
            level = "MINIMAL"
        
        return {
            "score": min(score, 100),  # Cap at 100
            "level": level,
            "factors": factors
        }
    
    def _generate_breach_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate breach analysis section."""
        if not events:
            return {
                "potential_breaches": [],
                "compromised_assets": [],
                "data_exposure_risk": "LOW",
                "containment_status": "N/A"
            }
        
        # Look for potential breach indicators
        breach_indicators = []
        critical_events = [e for e in events if e.severity == "CRITICAL"]
        
        for event in critical_events:
            if any(keyword in event.description.lower() for keyword in ["breach", "compromise", "exfiltration", "unauthorized access"]):
                breach_indicators.append({
                    "event_id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "description": event.description,
                    "severity": event.severity,
                    "source": event.source_type
                })
        
        # Identify potentially compromised assets
        compromised_assets = []
        asset_events = {}
        for event in events:
            if hasattr(event, 'affected_asset') and event.affected_asset:
                if event.affected_asset not in asset_events:
                    asset_events[event.affected_asset] = []
                asset_events[event.affected_asset].append(event)
        
        for asset, asset_event_list in asset_events.items():
            critical_count = sum(1 for e in asset_event_list if e.severity in ["CRITICAL", "HIGH"])
            if critical_count >= 3:  # Multiple high-severity events on same asset
                compromised_assets.append({
                    "asset": asset,
                    "total_events": len(asset_event_list),
                    "critical_events": critical_count,
                    "last_event": max(e.timestamp for e in asset_event_list).isoformat()
                })
        
        # Assess data exposure risk
        data_exposure_risk = "LOW"
        if len(breach_indicators) > 0:
            data_exposure_risk = "CRITICAL"
        elif len(compromised_assets) > 2:
            data_exposure_risk = "HIGH"
        elif len(compromised_assets) > 0:
            data_exposure_risk = "MEDIUM"
        
        # Containment status
        containment_status = "CONTAINED"
        if len(breach_indicators) > 0 or len(compromised_assets) > 0:
            containment_status = "INVESTIGATION_REQUIRED"
        
        return {
            "potential_breaches": breach_indicators,
            "compromised_assets": compromised_assets,
            "data_exposure_risk": data_exposure_risk,
            "containment_status": containment_status
        }
    
    def _generate_summary(self, stats: Dict[str, Any], risk_score: Dict[str, Any]) -> str:
        """Generate executive summary."""
        total_alerts = stats["total_alerts"]
        risk_level = risk_score["level"]
        
        if total_alerts == 0:
            return "No security events were detected during the reporting period. The security posture remains stable."
        
        severity_counts = stats["by_severity"]
        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)
        
        summary_parts = [
            f"During the past 7 days, {total_alerts} security events were detected.",
            f"The overall risk level is assessed as {risk_level} with a risk score of {risk_score['score']}/100."
        ]
        
        if critical_count > 0:
            summary_parts.append(f"{critical_count} critical severity events require immediate attention.")
        
        if high_count > 0:
            summary_parts.append(f"{high_count} high severity events were identified.")
        
        attack_patterns = stats.get("attack_patterns", [])
        if attack_patterns:
            summary_parts.append(f"{len(attack_patterns)} suspicious attack patterns were detected.")
        
        return " ".join(summary_parts)
    
    def _generate_recommendations(self, stats: Dict[str, Any], breach_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # High-level recommendations
        if stats["total_alerts"] > 100:
            recommendations.append("Consider implementing automated threat response to handle the high volume of security alerts.")
        
        # Severity-based recommendations
        critical_count = stats["by_severity"].get("CRITICAL", 0)
        if critical_count > 0:
            recommendations.append("Immediately investigate and respond to all critical severity events.")
        
        high_count = stats["by_severity"].get("HIGH", 0)
        if high_count > 10:
            recommendations.append("Review and prioritize response procedures for high severity events.")
        
        # Attack pattern recommendations
        attack_patterns = stats.get("attack_patterns", [])
        for pattern in attack_patterns:
            if pattern["type"] == "repeated_source":
                recommendations.append(f"Consider blocking or monitoring IP address {pattern['source_ip']} due to repeated suspicious activity.")
            elif pattern["type"] == "potential_brute_force":
                recommendations.append("Implement additional authentication controls to prevent brute force attacks.")
        
        # Breach analysis recommendations
        if breach_analysis["data_exposure_risk"] in ["HIGH", "CRITICAL"]:
            recommendations.append("Conduct immediate incident response procedures for potential data breach.")
        
        if breach_analysis["compromised_assets"]:
            recommendations.append("Isolate and forensically analyze potentially compromised assets.")
        
        # Source type recommendations
        source_counts = stats["by_source_type"]
        if source_counts.get("external", 0) > source_counts.get("internal", 0):
            recommendations.append("Strengthen perimeter security controls to address external threats.")
        
        return recommendations
    
    def format_as_json(self, report: Dict[str, Any]) -> str:
        """Format report as JSON string."""
        return json.dumps(report, indent=2, default=str)
    
    def format_as_html(self, report: Dict[str, Any]) -> str:
        """Format report as HTML for email delivery."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Weekly Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .risk-score { padding: 15px; border-radius: 5px; margin: 15px 0; font-weight: bold; }
        .risk-critical { background-color: #e74c3c; color: white; }
        .risk-high { background-color: #e67e22; color: white; }
        .risk-medium { background-color: #f39c12; color: white; }
        .risk-low { background-color: #27ae60; color: white; }
        .risk-minimal { background-color: #95a5a6; color: white; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .stats-table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        .stats-table th, .stats-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .stats-table th { background-color: #f2f2f2; }
        .recommendations