"""
Email service with pluggable backends.
Easy to switch from Resend to AWS SES later.
"""
import os
from typing import List, Optional
from enum import Enum
import resend

class EmailProvider(Enum):
    RESEND = "resend"
    AWS_SES = "aws_ses"
    SMTP = "smtp"

class EmailService:
    def __init__(self, provider: EmailProvider = EmailProvider.RESEND):
        self.provider = provider
        
        if provider == EmailProvider.RESEND:
            resend.api_key = os.getenv("RESEND_API_KEY")
            self.from_email = "GuardianOS <onboarding@resend.dev>"
        # Easy to add AWS SES later:
        # elif provider == EmailProvider.AWS_SES:
        #     self.ses_client = boto3.client('ses')
    
    async def send_alert_email(
        self,
        to_email: str,
        subject: str,
        alert_type: str,
        severity: str,
        description: str,
        details: dict
    ):
        """Send security alert email"""
        html_content = self._generate_alert_html(
            alert_type, severity, description, details
        )
        
        return await self._send_email(
            to=to_email,
            subject=f"🚨 GuardianOS Alert: {subject}",
            html=html_content
        )
    
    async def send_weekly_report(
        self,
        to_email: str,
        report_data: dict
    ):
        """Send weekly security summary"""
        html_content = self._generate_report_html(report_data)
        
        return await self._send_email(
            to=to_email,
            subject="📊 GuardianOS Weekly Security Report",
            html=html_content
        )
    
    async def _send_email(self, to: str, subject: str, html: str):
        """Internal method - switch providers here"""
        if self.provider == EmailProvider.RESEND:
            return self._send_via_resend(to, subject, html)
        # elif self.provider == EmailProvider.AWS_SES:
        #     return self._send_via_ses(to, subject, html)
    
    def _send_via_resend(self, to: str, subject: str, html: str):
        """Resend implementation"""
        try:
            params = {
                "from": self.from_email,
                "to": [to],
                "subject": subject,
                "html": html,
            }
            return resend.Emails.send(params)
        except Exception as e:
            print(f"Email send error: {e}")
            return None
    
    def _generate_alert_html(
        self, 
        alert_type: str, 
        severity: str, 
        description: str, 
        details: dict
    ) -> str:
        """Generate HTML email for alerts"""
        severity_colors = {
            "critical": "#EF4444",
            "high": "#F97316",
            "medium": "#F59E0B",
            "low": "#10B981",
            "info": "#3B82F6"
        }
        
        color = severity_colors.get(severity.lower(), "#6B7280")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%); 
                           color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 8px 8px; }}
                .alert-box {{ background: white; border-left: 4px solid {color}; 
                             padding: 20px; margin: 20px 0; border-radius: 4px; }}
                .severity {{ display: inline-block; padding: 6px 12px; background: {color}; 
                            color: white; border-radius: 4px; font-weight: bold; 
                            text-transform: uppercase; font-size: 12px; }}
                .footer {{ text-align: center; color: #64748b; font-size: 12px; 
                          margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; }}
                .button {{ display: inline-block; background: #7c3aed; color: white; 
                          padding: 12px 24px; text-decoration: none; border-radius: 6px; 
                          margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ GuardianOS Security Alert</h1>
                </div>
                <div class="content">
                    <div class="alert-box">
                        <p><span class="severity">{severity}</span></p>
                        <h2 style="margin: 15px 0;">{alert_type}</h2>
                        <p style="color: #475569; font-size: 16px;">{description}</p>
                        
                        {self._format_details_html(details)}
                    </div>
                    
                    <a href="https://cybersec-suite-production.up.railway.app/dashboard/alerts" 
                       class="button">View in Dashboard</a>
                    
                    <div class="footer">
                        <p>This is an automated security alert from GuardianOS</p>
                        <p>© 2025 GuardianOS. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _format_details_html(self, details: dict) -> str:
        """Format details dictionary as HTML"""
        if not details:
            return ""
        
        html = "<div style='margin-top: 20px; padding-top: 20px; border-top: 1px solid #e2e8f0;'>"
        html += "<h3 style='color: #475569;'>Details:</h3><ul style='color: #64748b;'>"
        
        for key, value in details.items():
            html += f"<li><strong>{key}:</strong> {value}</li>"
        
        html += "</ul></div>"
        return html
    
    def _generate_report_html(self, report_data: dict) -> str:
        """Generate HTML email for weekly reports"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%); 
                           color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f8fafc; padding: 30px; }}
                .stat-box {{ background: white; padding: 20px; margin: 10px 0; 
                            border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
                .stat-number {{ font-size: 36px; font-weight: bold; color: #7c3aed; }}
                .stat-label {{ color: #64748b; font-size: 14px; }}
                .footer {{ text-align: center; color: #64748b; font-size: 12px; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Weekly Security Report</h1>
                    <p style="margin: 0; opacity: 0.9;">{report_data.get('date_range', 'Past 7 Days')}</p>
                </div>
                <div class="content">
                    <div class="stat-box">
                        <div class="stat-number">{report_data.get('total_events', 0)}</div>
                        <div class="stat-label">Total Security Events</div>
                    </div>
                    
                    <div class="stat-box">
                        <h3>Events by Severity</h3>
                        <ul>
                            <li>Critical: {report_data.get('severity_counts', {}).get('critical', 0)}</li>
                            <li>High: {report_data.get('severity_counts', {}).get('high', 0)}</li>
                            <li>Medium: {report_data.get('severity_counts', {}).get('medium', 0)}</li>
                            <li>Low: {report_data.get('severity_counts', {}).get('low', 0)}</li>
                        </ul>
                    </div>
                    
                    <div class="stat-box">
                        <h3>Risk Score</h3>
                        <div class="stat-number">{report_data.get('risk_score', 0)}/100</div>
                    </div>
                    
                    <div class="footer">
                        <p>© 2025 GuardianOS. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

# Global instance (easy to switch provider)
email_service = EmailService(provider=EmailProvider.RESEND)