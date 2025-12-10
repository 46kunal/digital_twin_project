# notifications.py
import logging
from flask_mail import Message
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger("notifications")

def send_scan_completion_email(app, scan_id):
    """Send email notification when scan completes"""
    from models import db, Scan, Vulnerability
    
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return
        
        vuln_count = Vulnerability.query.filter_by(scan_id=scan_id).count()
        high_count = Vulnerability.query.filter_by(scan_id=scan_id).filter(
            Vulnerability.severity.ilike('%high%') | Vulnerability.severity.ilike('%crit%')
        ).count()
        
        if high_count == 0:
            return  # Only send email if high-severity vulns found
        
        mail = app.mail
        
        msg = Message(
            subject=f'⚠️ Security Alert: {high_count} High-Severity Vulnerabilities Detected',
            recipients=[app.config.get('MAIL_USERNAME')],  # Change to security team email
            body=f"""
Security Scan Completed

Scan ID: {scan_id}
Target: {scan.target}
Total Vulnerabilities: {vuln_count}
High/Critical: {high_count}

Please review the scan results in the dashboard.

Time: {scan.end_time or 'In Progress'}
            """
        )
        
        try:
            mail.send(msg)
            logger.info(f"Email notification sent for scan {scan_id}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")

def send_slack_notification(scan_id):
    """Send Slack notification when scan completes"""
    from models import db, Scan, Vulnerability
    from config import Config
    
    if not Config.SLACK_BOT_TOKEN:
        logger.debug("Slack token not configured, skipping notification")
        return
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return
    
    vuln_count = Vulnerability.query.filter_by(scan_id=scan_id).count()
    high_count = Vulnerability.query.filter_by(scan_id=scan_id).filter(
        Vulnerability.severity.ilike('%high%') | Vulnerability.severity.ilike('%crit%')
    ).count()
    
    client = WebClient(token=Config.SLACK_BOT_TOKEN)
    
    emoji = "🔴" if high_count > 0 else "🟢"
    
    message = f"""{emoji} *Scan Completed*
*Target:* `{scan.target}`
*Vulnerabilities:* {vuln_count} ({high_count} High/Critical)
*Scan ID:* #{scan_id}
*Status:* {scan.status}
"""
    
    try:
        client.chat_postMessage(
            channel=Config.SLACK_CHANNEL,
            text=message
        )
        logger.info(f"Slack notification sent for scan {scan_id}")
    except SlackApiError as e:
        logger.error(f"Slack API error: {e.response['error']}")
