import os
import datetime
import logging
from pathlib import Path

from fpdf import FPDF
from models import db, Scan, Vulnerability, VM


logger = logging.getLogger(__name__)


class ScanReportPDF(FPDF):
    COLORS = {
        'primary': (0, 145, 234),
        'accent': (0, 229, 255),
        'critical': (255, 71, 71),
        'high': (255, 152, 0),
        'medium': (255, 211, 61),
        'low': (81, 207, 102),
        'text': (50, 50, 50),
        'muted': (100, 100, 100),
        'gray': (128, 128, 128),
    }

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_author('Aegis Security Platform')

    def set_color(self, name: str):
        color = self.COLORS.get(name)
        if not color:
            raise ValueError(f"Unknown color name: {name}")
        self.set_text_color(*color)

    def header(self):
        # Logo / title
        self.set_font('Arial', 'B', 16)
        self.set_color('primary')
        self.cell(0, 10, 'Aegis Security Platform', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.set_color('muted')
        self.cell(0, 5, 'Vulnerability Scan Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_color('gray')
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_color('primary')
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(2)

    def section_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(0, 0, 0)
        self.cell(0, 8, title, 0, 1, 'L')
        self.ln(1)

    def body_text(self, text):
        self.set_font('Arial', '', 11)
        self.set_color('text')
        self.multi_cell(0, 6, text)
        self.ln(2)


def _severity_key(severity: str) -> str:
    if not severity:
        return 'low'
    s = severity.lower()
    if 'crit' in s:
        return 'critical'
    if 'high' in s:
        return 'high'
    if 'medium' in s:
        return 'medium'
    if 'low' in s:
        return 'low'
    return 'low'


def _truncate(text: str, max_len: int = 200) -> str:
    if not text or len(text) <= max_len:
        return text or ''
    chunk = text[:max_len]
    if ' ' in chunk:
        chunk = chunk.rsplit(' ', 1)[0]
    return chunk + '...'


def generate_scan_report(scan_id):
    """Generate PDF report for a completed scan."""
    if not scan_id:
        raise ValueError("Scan ID cannot be empty")

    scan = db.session.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    # Optional: only allow completed scans
    if scan.status and scan.status.lower() not in ('completed', 'failed'):
        raise ValueError(f"Cannot generate report for scan in '{scan.status}' status")

    # Get vulnerabilities
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()

    # Single-pass severity counts
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for v in vulnerabilities:
        severity_counts[_severity_key(v.severity)] += 1

    critical = severity_counts['critical']
    high = severity_counts['high']
    medium = severity_counts['medium']
    low = severity_counts['low']
    total = len(vulnerabilities)

    # Get VM if available (using first vuln as hint, same as original)
    vm = None
    if vulnerabilities:
        vm_id = vulnerabilities[0].vm_id
        if vm_id:
            vm = db.session.get(VM, vm_id)

    # Create PDF
    pdf = ScanReportPDF()
    pdf.set_title(f'Security Scan Report - {scan.target}')
    pdf.set_subject('Security vulnerability scan results')
    pdf.add_page()

    # Title page
    pdf.set_font('Arial', 'B', 24)
    pdf.set_color('accent')
    pdf.ln(30)
    pdf.cell(0, 15, 'Security Scan Report', 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font('Arial', '', 14)
    pdf.set_color('muted')
    pdf.cell(0, 8, f'Scan ID: {scan.id}', 0, 1, 'C')
    pdf.cell(0, 8, f'Target: {scan.target}', 0, 1, 'C')
    date_str = scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else "N/A"
    pdf.cell(0, 8, f'Date: {date_str}', 0, 1, 'C')

    # Executive Summary
    pdf.add_page()
    pdf.chapter_title('Executive Summary')

    pdf.body_text(
        f'This report presents the results of a security vulnerability scan conducted on {scan.target}.'
    )
    pdf.body_text(f'Total vulnerabilities discovered: {total}')
    pdf.ln(5)

    # Severity breakdown
    pdf.section_title('Severity Breakdown')
    pdf.set_font('Arial', '', 11)

    pdf.set_color('critical')
    pdf.cell(0, 6, f'Critical: {critical}', 0, 1)

    pdf.set_color('high')
    pdf.cell(0, 6, f'High: {high}', 0, 1)

    pdf.set_color('medium')
    pdf.cell(0, 6, f'Medium: {medium}', 0, 1)

    pdf.set_color('low')
    pdf.cell(0, 6, f'Low: {low}', 0, 1)
    pdf.ln(5)

    # Risk assessment
    pdf.section_title('Risk Assessment')
    if critical > 0 or high > 0:
        risk_level = 'HIGH RISK'
        risk_color = 'critical'
        recommendation_summary = (
            'Immediate action required. Critical and high-severity vulnerabilities pose significant security risks.'
        )
    elif medium > 0:
        risk_level = 'MEDIUM RISK'
        risk_color = 'medium'
        recommendation_summary = (
            'Medium-severity vulnerabilities should be addressed in a timely manner.'
        )
    else:
        risk_level = 'LOW RISK'
        risk_color = 'low'
        recommendation_summary = (
            'No critical vulnerabilities detected. Continue monitoring.'
        )

    pdf.set_font('Arial', 'B', 12)
    pdf.set_color(risk_color)
    pdf.cell(0, 8, f'Overall Risk Level: {risk_level}', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.set_color('text')
    pdf.multi_cell(0, 6, recommendation_summary)
    pdf.ln(5)

    # Scan details
    pdf.add_page()
    pdf.chapter_title('Scan Details')
    pdf.section_title('Target Information')

    pdf.body_text(f'Target: {scan.target}')
    pdf.body_text(f'Scan ID: {scan.id}')
    pdf.body_text(f'Status: {scan.status}')
    pdf.body_text(
        f'Start Time: {scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else "N/A"}'
    )
    pdf.body_text(
        f'End Time: {scan.end_time.strftime("%Y-%m-%d %H:%M:%S") if scan.end_time else "In progress"}'
    )

    if vm:
        pdf.body_text(f'Hostname: {vm.hostname}')
        pdf.body_text(f'Operating System: {vm.os}')

    pdf.ln(5)

    # Detailed vulnerabilities
    if vulnerabilities:
        pdf.add_page()
        pdf.chapter_title('Vulnerability Details')

        groups = [
            ('Critical', lambda v: _severity_key(v.severity) == 'critical'),
            ('High', lambda v: _severity_key(v.severity) == 'high'),
            ('Medium', lambda v: _severity_key(v.severity) == 'medium'),
            ('Low', lambda v: _severity_key(v.severity) == 'low'),
        ]

        for severity_name, severity_filter in groups:
            severity_vulns = [v for v in vulnerabilities if severity_filter(v)]
            if not severity_vulns:
                continue

            pdf.section_title(
                f'{severity_name} Severity Vulnerabilities ({len(severity_vulns)})'
            )

            for idx, vuln in enumerate(severity_vulns[:10], 1):  # Limit to 10 per severity
                pdf.set_font('Arial', 'B', 10)
                pdf.set_color('primary')

                # Build title: issue_id + service/port
                title = vuln.issue_id or vuln.cve_id or 'Unknown issue'
                if vuln.service or vuln.port:
                    svc_part = vuln.service or 'service'
                    if vuln.port:
                        svc_part += f' on port {vuln.port}'
                    title = f'{title} ({svc_part})'

                pdf.cell(0, 6, f'{idx}. {title}', 0, 1)

                pdf.set_font('Arial', '', 9)
                pdf.set_color('text')

                # Risk-based fields (newer model fields)
                if getattr(vuln, 'risk_score', None) is not None:
                    pdf.cell(0, 5, f'Risk Score: {vuln.risk_score}', 0, 1)
                if getattr(vuln, 'likelihood', None):
                    pdf.cell(0, 5, f'Likelihood: {vuln.likelihood}', 0, 1)
                if getattr(vuln, 'impact', None):
                    pdf.cell(0, 5, f'Impact: {vuln.impact}', 0, 1)

                # Legacy-style fields
                if vuln.severity:
                    pdf.cell(0, 5, f'Severity: {vuln.severity}', 0, 1)
                if getattr(vuln, 'cvss_score', None) is not None:
                    pdf.cell(0, 5, f'CVSS Score: {vuln.cvss_score}', 0, 1)
                if vuln.version:
                    pdf.cell(0, 5, f'Version: {vuln.version}', 0, 1)
                if getattr(vuln, 'cpe', None):
                    pdf.cell(0, 5, f'CPE: {vuln.cpe}', 0, 1)

                # Description
                if vuln.description:
                    desc = _truncate(vuln.description, 200)
                    pdf.multi_cell(0, 5, f'Description: {desc}')

                pdf.ln(3)

            if len(severity_vulns) > 10:
                pdf.set_font('Arial', 'I', 9)
                pdf.set_color('muted')
                pdf.cell(
                    0,
                    5,
                    f'+ {len(severity_vulns) - 10} more {severity_name.lower()} vulnerabilities...',
                    0,
                    1,
                )

            pdf.ln(5)

    # Recommendations
    pdf.add_page()
    pdf.chapter_title('Recommendations')

    recs = []
    if critical > 0:
        recs.append(
            'Address all CRITICAL vulnerabilities immediately, as they pose severe security risks.'
        )
    if high > 0:
        recs.append(
            'Remediate HIGH severity vulnerabilities as a priority to reduce exposure.'
        )
    if medium > 0:
        recs.append(
            'Plan to fix MEDIUM severity issues in upcoming maintenance windows.'
        )

    recs.extend(
        [
            'Implement a regular scanning schedule (weekly or monthly).',
            'Keep all systems and software up to date with the latest security patches.',
            'Review and harden network configurations and firewall rules.',
            'Implement intrusion detection and prevention systems (IDS/IPS).',
            'Conduct security awareness training for all personnel.',
        ]
    )

    for idx, rec in enumerate(recs, 1):
        pdf.body_text(f'{idx}. {rec}')
        pdf.ln(2)

    # Save PDF
    base_dir = Path(__file__).resolve().parent.parent
    output_dir = base_dir / 'reports' / 'generated'

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f'Failed to create reports directory: {e}')
        raise RuntimeError(f'Failed to create reports directory: {e}')

    filename = f'scan_{scan_id}_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    output_path = output_dir / filename

    pdf.output(str(output_path))
    return str(output_path)
