# app.py

import threading
import datetime
import os
import sys
import logging
import tempfile
import shutil
import re
import subprocess
from functools import wraps
from typing import Iterable, Optional
from ipaddress import ip_network, AddressValueError

# Ensure project root is on sys.path so subpackages import reliably
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, send_file, after_this_request
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, verify_jwt_in_request, get_jwt, get_jwt_identity
from flask_socketio import SocketIO, emit
from flask_mail import Mail

# Local app modules
from config import Config
from models import db, User, RevokedToken, ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from scanner import run_scan
from auth import auth_bp

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("digital_twin_app")

# Globals for scan-locking
running_scans = set()
running_scans_lock = threading.Lock()
running_scan_map = {}

_MODE_ESTIMATE = {
    "fast": "≈2m per host",
    "medium": "≈6m per host",
    "full": "≈15m per host"
}


def normalize_target(t: Optional[str]) -> Optional[str]:
    if not t:
        return t
    return t.strip().lower()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # DB / Migrations
    db.init_app(app)
    Migrate(app, db)

    # Mail (Flask-Mail)
    mail = Mail(app)
    app.mail = mail

    # CORS
    cors_origins = app.config.get('CORS_ORIGINS', [
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ])
    CORS(app,
         resources={r"/api/*": {"origins": cors_origins}},
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization", "X-CSRF-TOKEN"],
         expose_headers=["Set-Cookie"],
         methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
         )

    # SocketIO for real-time updates - FIXED configuration
    socketio = SocketIO(
        app,
        cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
        async_mode='threading',
        logger=False,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25,
        cors_credentials=True,
        manage_session=False
    )
    app.socketio = socketio

    # JWT
    jwt = JWTManager(app)
    app.register_blueprint(auth_bp)

    # Optional: register VM blueprint if provided
    try:
        from api.vm_routes import vm_bp
        if vm_bp.name not in app.blueprints:
            app.register_blueprint(vm_bp, url_prefix='/api')
            logger.info("Registered VM blueprint from api.vm_routes")
    except Exception:
        logger.debug("api.vm_routes not present; continuing", exc_info=True)

    # ---------------- JWT callbacks ----------------
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload.get("jti")
        if not jti:
            return True
        return RevokedToken.is_revoked(jti)

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"msg": "token expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(err):
        return jsonify({"msg": "invalid token", "error": str(err)}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(err):
        return jsonify({"msg": "missing token", "error": str(err)}), 401

    # ---------------- Role decorator ----------------
    def role_required(roles: Iterable[str]):
        if isinstance(roles, str):
            allowed = {roles}
        else:
            allowed = set(roles)

        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                verify_jwt_in_request()
                claims = get_jwt()
                role = claims.get("role")
                if role not in allowed:
                    return jsonify({"msg": "forbidden - insufficient role"}), 403
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    app.role_required = role_required

    # ================= SOCKETIO EVENTS =================
    @socketio.on('connect')
    def handle_connect():
        logger.info("Client connected to SocketIO")
        emit('connected', {'status': 'connected'})

    @socketio.on('disconnect')
    def handle_disconnect():
        logger.info("Client disconnected from SocketIO")

    @socketio.on('subscribe_scan')
    def handle_subscribe(data):
        scan_id = data.get('scan_id')
        logger.info(f"Client subscribed to scan {scan_id}")

    # ================= DASHBOARD ENDPOINTS =================
    @app.route('/api/summary', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_summary():
        from models import VM, Vulnerability, Scan
        total_vms = VM.query.count()
        try:
            # Use numeric threshold for "at risk" mapping (risk_score 1..25)
            # Treat risk_score >= 15 as High (adjust threshold as desired)
            at_risk_vms_count = (
                db.session.query(VM.id)
                .join(Vulnerability)
                .filter(Vulnerability.risk_score >= 15)
                .distinct()
                .count()
            )
        except Exception:
            # Fallback to severity string checks if numeric comparison fails
            at_risk_vms_count = (
                db.session.query(VM.id)
                .join(Vulnerability)
                .filter(Vulnerability.severity.ilike('%crit%') | Vulnerability.severity.ilike('%high%'))
                .distinct()
                .count()
            )
        last_scan = Scan.query.order_by(Scan.start_time.desc()).first()
        summary = {
            'totalVMs': total_vms,
            'healthyVMs': max(0, total_vms - at_risk_vms_count),
            'atRiskVMs': at_risk_vms_count,
            'lastScan': last_scan.start_time.isoformat() if last_scan and last_scan.start_time else None
        }
        return jsonify(summary)

    @app.route('/api/vulnerabilities/by-severity', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_vulnerabilities_by_severity():
        from models import Vulnerability
        try:
            critical = Vulnerability.query.filter(Vulnerability.severity.ilike('%crit%')).count()
            high = Vulnerability.query.filter(Vulnerability.severity.ilike('%high%')).count()
            medium = Vulnerability.query.filter(Vulnerability.severity.ilike('%medium%')).count()
            low = Vulnerability.query.filter(Vulnerability.severity.ilike('%low%')).count()
        except Exception:
            critical = high = medium = low = 0
        return jsonify({'critical': critical, 'high': high, 'medium': medium, 'low': low})

    @app.route('/api/scans/recent', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_recent_scans():
        from models import Scan, Vulnerability
        scans = Scan.query.order_by(Scan.start_time.desc()).limit(10).all()
        scans_data = []
        for scan in scans:
            count = Vulnerability.query.filter_by(scan_id=scan.id).count()
            high_count = (
                Vulnerability.query.filter_by(scan_id=scan.id)
                .filter(Vulnerability.severity.ilike('%high%') | Vulnerability.severity.ilike('%crit%'))
                .count()
            )
            scans_data.append({
                'id': scan.id,
                'target': scan.target,
                'startTime': scan.start_time.isoformat() if scan.start_time else None,
                'status': scan.status,
                'vulnerabilityCount': count,
                'highCritCount': high_count,
                'eta': scan.eta,
                'progress': scan.progress,
                'phase': scan.phase
            })
        return jsonify(scans_data)

    @app.route('/api/scans', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_all_scans():
        from models import Scan
        try:
            page = int(request.args.get('page', 1))
        except Exception:
            page = 1
        try:
            per_page = int(request.args.get('per_page', 50))
        except Exception:
            per_page = 50
        per_page = max(1, min(500, per_page))
        qry = Scan.query.order_by(Scan.start_time.desc())
        pag = qry.paginate(page=page, per_page=per_page, error_out=False)
        out = []
        for s in pag.items:
            out.append({
                'id': s.id,
                'target': s.target,
                'status': s.status,
                'phase': s.phase,
                'progress': s.progress,
                'eta': s.eta,
                'start_time': s.start_time.isoformat() if s.start_time else None,
                'end_time': s.end_time.isoformat() if s.end_time else None
            })
        return jsonify({
            'page': pag.page,
            'per_page': pag.per_page,
            'total': pag.total,
            'pages': pag.pages,
            'items': out
        })

    # ================= SCAN CONTROL =================
    @app.route('/api/scan/start', methods=['POST'])
    @role_required(["Analyst", "Admin"])
    def start_scan():
        from models import Scan
        data = request.get_json(silent=True) or {}
        target = data.get('target')
        mode = data.get('mode', 'fast')
        parse_xml = bool(data.get('parse_xml', True))
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        normalized = normalize_target(target)
        
        with running_scans_lock:
            if normalized in running_scans:
                return jsonify({'error': 'Scan already running for this target'}), 409
            running_scans.add(normalized)
        
        new_scan = Scan(
            target=target.strip(),
            status='queued',
            start_time=datetime.datetime.now(datetime.timezone.utc),
            eta=_MODE_ESTIMATE.get(mode, ""),
            progress=0,
            phase='queued'
        )
        db.session.add(new_scan)
        db.session.commit()
        scan_id = new_scan.id
        running_scan_map[normalized] = scan_id

        def emit_progress(sid, progress, phase, status='running', message=''):
            """Helper function to emit progress updates"""
            try:
                # Update database
                with app.app_context():
                    from models import Scan as ScanModel
                    s = db.session.get(ScanModel, sid)
                    if s:
                        s.progress = progress
                        s.phase = phase
                        s.status = status
                        # Append to log_data
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        log_entry = f"[{timestamp}] [{phase}] {progress}% - {message}"
                        if hasattr(s, 'log_data') and s.log_data:
                            s.log_data = s.log_data + '\n' + log_entry
                        else:
                            # keep compatibility with older 'log'
                            if hasattr(s, 'log') and s.log:
                                s.log = s.log + '\n' + log_entry
                            else:
                                s.log_data = log_entry
                        db.session.commit()
                
                # Emit via SocketIO
                socketio.emit('scan_progress', {
                    'scan_id': sid,
                    'progress': progress,
                    'phase': phase,
                    'status': status,
                    'message': message,
                    'timestamp': datetime.datetime.now().isoformat()
                })
                logger.info(f"✅ Emitted: Scan {sid} - {progress}% - {phase}")
            except Exception as e:
                logger.error(f"❌ Failed to emit progress: {e}")

        def _worker(scan_id_local, tgt_normalized, host_target, mode_local, parse_xml_local):
            try:
                with app.app_context():
                    # Emit scan starting
                    emit_progress(scan_id_local, 5, 'starting', 'running', 'Initializing scan...')
                    
                    # Also emit legacy event for compatibility
                    socketio.emit('scan_update', {
                        'scan_id': scan_id_local,
                        'status': 'running',
                        'progress': 5,
                        'phase': 'starting'
                    })
                    
                    # Run the actual scan
                    run_scan(scan_id_local, host_target, mode=mode_local, parse_xml=parse_xml_local)
                    
                    # Emit scan completed
                    emit_progress(scan_id_local, 100, 'completed', 'completed', 'Scan completed successfully')
                    
                    socketio.emit('scan_update', {
                        'scan_id': scan_id_local,
                        'status': 'completed',
                        'progress': 100,
                        'phase': 'completed'
                    })
                    
                    # Update end time
                    from models import Scan as ScanModel
                    s = db.session.get(ScanModel, scan_id_local)
                    if s:
                        s.end_time = datetime.datetime.now(datetime.timezone.utc)
                        db.session.commit()
                    
                    # Send notifications
                    try:
                        from notifications import send_scan_completion_email
                        send_scan_completion_email(app, scan_id_local)
                    except Exception as e:
                        logger.error("Email notification failed: %s", e)
                    try:
                        from notifications import send_slack_notification
                        send_slack_notification(scan_id_local)
                    except Exception as e:
                        logger.error("Slack notification failed: %s", e)
                        
            except Exception as e:
                logger.exception("Background scan failed: %s", e)
                try:
                    with app.app_context():
                        from models import Scan as ScanModel
                        s = db.session.get(ScanModel, scan_id_local)
                        if s:
                            s.status = 'failed'
                            s.phase = 'internal_error'
                            s.progress = 100
                            s.end_time = datetime.datetime.now(datetime.timezone.utc)
                            # Append error to log_data
                            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            error_log = f"[{timestamp}] [ERROR] Scan failed: {e}"
                            if hasattr(s, 'log_data') and s.log_data:
                                s.log_data = s.log_data + '\n' + error_log
                            else:
                                if hasattr(s, 'log') and s.log:
                                    s.log = s.log + '\n' + error_log
                                else:
                                    s.log_data = error_log
                            db.session.commit()
                        
                        socketio.emit('scan_progress', {
                            'scan_id': scan_id_local,
                            'progress': 100,
                            'phase': 'failed',
                            'status': 'failed',
                            'message': str(e)
                        })
                        socketio.emit('scan_update', {
                            'scan_id': scan_id_local,
                            'status': 'failed',
                            'phase': 'error'
                        })
                except Exception:
                    logger.exception("Failed updating Scan status after worker exception")
            finally:
                with running_scans_lock:
                    running_scans.discard(tgt_normalized)
                running_scan_map.pop(tgt_normalized, None)

        thread = threading.Thread(
            target=_worker,
            args=(scan_id, normalized, target, mode, parse_xml),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'message': f'Scan queued for target: {target}',
            'scan_id': scan_id,
            'mode': mode
        }), 202

    @app.route('/api/scan/status/<int:scan_id>', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_scan_status(scan_id):
        from models import Scan
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get log lines - check both log and log_data for compatibility
        log_lines = []
        if hasattr(scan, 'log_data') and scan.log_data:
            log_lines = scan.log_data.splitlines()[-50:]
        elif hasattr(scan, 'log') and scan.log:
            log_lines = scan.log.splitlines()[-50:]
        
        return jsonify({
            'scan_id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.phase,
            'eta': scan.eta,
            'log_tail': log_lines,
            'start_time': scan.start_time.isoformat() if scan.start_time else None,
            'end_time': scan.end_time.isoformat() if scan.end_time else None
        })

    # ------------------ UPDATED: Scan detail with risk fields ------------------
    @app.route('/api/scan/<int:scan_id>', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_scan_detail(scan_id):
        from models import Scan, Vulnerability
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # Get vulnerabilities for this scan
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()

        # Get log lines - check both log and log_data for compatibility
        log_lines = []
        if hasattr(scan, 'log_data') and scan.log_data:
            log_lines = scan.log_data.splitlines()
        elif hasattr(scan, 'log') and scan.log:
            log_lines = scan.log.splitlines()

        # Calculate duration
        duration_seconds = None
        if scan.start_time and scan.end_time:
            duration_seconds = (scan.end_time - scan.start_time).total_seconds()

        return jsonify({
            'scan_id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.phase,
            'eta': scan.eta,
            'log': log_lines,
            'log_data': scan.log_data if hasattr(scan, 'log_data') else None,
            'raw_output_head': (scan.raw_output or "")[:2000] if hasattr(scan, 'raw_output') else "",
            'start_time': scan.start_time.isoformat() if scan.start_time else None,
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration_seconds': duration_seconds,
            'vulnerability_count': len(vulns),
            'vulnerabilities': [{
                'id': v.id,
                'issue_id': getattr(v, 'issue_id', None),
                'likelihood': (v.likelihood or 'Unknown'),
                'impact': (v.impact or 'Unknown'),
                'risk_score': getattr(v, 'risk_score', None),
                'severity': (v.severity or 'Unknown'),
                'port': v.port,
                'service': v.service,
                'version': v.version,
                'description': v.description,
                'cpe': v.cpe,
                'remediation_status': getattr(v, 'remediation_status', 'open'),
                # legacy fields (kept for compatibility)
                'cve_id': v.cve_id,
                'cvss_score': v.cvss_score,
            } for v in vulns]
        })

    # ------------------ UPDATED: vulnerabilities for a scan (risk fields) ------------------
    @app.route('/api/scan/<int:scan_id>/vulnerabilities', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_scan_vulnerabilities(scan_id):
        from models import Vulnerability
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
        return jsonify([{
            'id': v.id,
            'issue_id': getattr(v, 'issue_id', None),
            'likelihood': (v.likelihood or 'Unknown'),
            'impact': (v.impact or 'Unknown'),
            'risk_score': getattr(v, 'risk_score', None),
            'severity': (v.severity or 'Unknown'),
            'port': v.port,
            'service': v.service,
            'version': v.version,
            'description': v.description,
            'cpe': v.cpe,
            'remediation_status': getattr(v, 'remediation_status', 'open'),
            # legacy fields (kept for compatibility)
            'cve_id': v.cve_id,
            'cvss_score': v.cvss_score,
        } for v in vulns])

    # ------------------ UPDATED: vulnerabilities for a VM (risk fields) ------------------
    @app.route('/api/vm/<int:vm_id>/vulnerabilities', methods=['GET'])
    @role_required(["Viewer", "Analyst", "Admin"])
    def get_vm_vulnerabilities(vm_id):
        from models import Vulnerability
        vulns = Vulnerability.query.filter_by(vm_id=vm_id).all()
        return jsonify([{
            'id': v.id,
            'issue_id': getattr(v, 'issue_id', None),
            'likelihood': (v.likelihood or 'Unknown'),
            'impact': (v.impact or 'Unknown'),
            'risk_score': getattr(v, 'risk_score', None),
            'severity': (v.severity or 'Unknown'),
            'port': v.port,
            'service': v.service,
            'version': v.version,
            'description': v.description,
            'scan_id': v.scan_id,
            # legacy optional
            'cve_id': v.cve_id,
            'cvss_score': v.cvss_score,
        } for v in vulns])

    # ================= VM DISCOVERY =================
    @app.route('/api/vm/discover', methods=['POST'])
    @role_required(["Analyst", "Admin"])
    def discover_vms():
        from models import VM
        data = request.get_json(silent=True) or {}
        network_range = data.get('network', '192.168.1.0/24')

        try:
            ip_network(network_range, strict=False)
        except (ValueError, AddressValueError):
            return jsonify({'error': 'Invalid network/CIDR provided'}), 400

        if not shutil.which("nmap"):
            return jsonify({'error': 'nmap binary not found on server'}), 500

        caller = None
        try:
            claims = get_jwt()
            caller = claims.get("sub") or claims.get("identity")
        except Exception:
            caller = "unknown"

        logger.info("Starting VM discovery for %s by %s", network_range, caller)

        cmd = ["nmap", "-sn", "-oG", "-", network_range]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            logger.warning("VM discovery timed out for network: %s", network_range)
            return jsonify({'error': 'Discovery timeout'}), 408
        except Exception as e:
            logger.exception("nmap execution failed")
            return jsonify({'error': f'nmap execution failed: {e}'}), 500

        stdout = result.stdout or ""
        discovered = []
        total_up = 0
        for line in stdout.splitlines():
            if 'Status: Up' in line:
                total_up += 1
                ip_match = re.search(r'Host:\s*([\d\.]+)', line)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                hostname_match = re.search(r'Host: [\d\.]+ \(([^)]*)\)', line)
                hostname = hostname_match.group(1) if hostname_match and hostname_match.group(1) else f'host-{ip.split(".")[-1]}'
                existing = VM.query.filter_by(ip_address=ip).first()
                if existing:
                    continue
                vm = VM(ip_address=ip, hostname=hostname, os='Unknown')
                db.session.add(vm)
                discovered.append({'ip': ip, 'hostname': hostname})
        try:
            if discovered:
                db.session.commit()
            else:
                db.session.rollback()
        except Exception:
            logger.exception("Failed committing discovered VMs")
            try:
                db.session.rollback()
            except Exception:
                pass
            return jsonify({'error': 'database commit failed'}), 500

        return jsonify({
            'message': f'Discovery complete. Found {len(discovered)} new VMs (total up: {total_up})',
            'discovered': discovered,
            'total_up': total_up,
            'nmap_rc': result.returncode
        }), 200

    @app.route('/api/vm/detect-network', methods=['GET'])
    @role_required(["Analyst", "Admin"])
    def detect_network():
        default_network = '192.168.56.0/24'
        try:
            import netifaces
        except Exception:
            logger.debug("netifaces not installed; returning default network", exc_info=True)
            return jsonify({'network': default_network, 'detected': False}), 200

        try:
            interfaces = netifaces.interfaces()
            host_only = None

            for iface in interfaces:
                if 'vboxnet' in iface.lower() or 'virtualbox' in iface.lower() or iface.lower().startswith('vbox'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        addr_info = addrs[netifaces.AF_INET][0]
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        if ip and netmask:
                            try:
                                net = ip_network(f"{ip}/{netmask}", strict=False)
                                host_only = str(net)
                                break
                            except Exception:
                                pass

            if host_only:
                return jsonify({'network': host_only, 'detected': True}), 200
            else:
                return jsonify({'network': default_network, 'detected': False}), 200
        except Exception as e:
            logger.exception("Network detection failed")
            return jsonify({'network': default_network, 'detected': False, 'error': str(e)}), 200

    # ================= REPORTING ENDPOINTS =================
    
    # NEW: PDF report endpoint that frontend expects
    @app.route('/api/scan/<int:scan_id>/report/pdf', methods=['GET'])
    @role_required(["Analyst", "Admin"])
    def get_scan_pdf_report(scan_id):
        """Generate PDF report for a specific scan - matches frontend URL"""
        try:
            from reporting.pdf_generator import generate_scan_report
        except Exception as e:
            logger.exception("PDF generator import failed")
            return jsonify({"error": "PDF generator unavailable", "detail": str(e)}), 500

        try:
            pdf_path = generate_scan_report(scan_id)
            if not pdf_path or not os.path.exists(pdf_path):
                return jsonify({"error": "Report generation failed"}), 500

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=f"scan_{scan_id}_report.pdf",
                mimetype='application/pdf'
            )
        except Exception as e:
            logger.exception("PDF generation failed for scan %s", scan_id)
            return jsonify({"error": "PDF generation failed", "detail": str(e)}), 500
    
    @app.route('/api/reports/<int:scan_id>', methods=['GET'])
    @role_required(["Analyst", "Admin"])
    def generate_report(scan_id):
        try:
            from reporting.pdf_generator import generate_scan_report
        except Exception as e:
            logger.exception("PDF generator import failed")
            return jsonify({"error": "PDF generator unavailable", "detail": str(e)}), 500

        try:
            pdf_path = generate_scan_report(scan_id)
            if not pdf_path or not os.path.exists(pdf_path):
                return jsonify({"error": "Report generation failed"}), 500

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=f"scan_{scan_id}_report.pdf",
                mimetype='application/pdf'
            )
        except Exception as e:
            logger.exception("Report generation failed for scan %s", scan_id)
            return jsonify({"error": "PDF generation failed", "detail": str(e)}), 500

    @app.route('/api/reports/bulk', methods=['POST'])
    @role_required(["Analyst", "Admin"])
    def generate_bulk_reports():
        data = request.get_json(silent=True) or {}
        scan_ids = data.get("scan_ids") or data.get("scans") or []
        fmt = (data.get("format") or "pdf").lower()

        if not isinstance(scan_ids, (list, tuple)) or len(scan_ids) == 0:
            return jsonify({"error": "Please provide scan_ids as a non-empty list"}), 400

        if fmt != "pdf":
            return jsonify({"error": f"Unsupported format: {fmt}. Only 'pdf' is supported"}), 400

        try:
            from reporting.pdf_generator import generate_scan_report
        except Exception as e:
            logger.exception("PDF generator import failed")
            return jsonify({"error": "PDF generator unavailable", "detail": str(e)}), 500

        tmpdir = tempfile.mkdtemp(prefix="scan_reports_")
        pdf_paths = []
        errors = []

        try:
            for sid in scan_ids:
                try:
                    pdf_path = generate_scan_report(int(sid))
                    if not pdf_path or not os.path.exists(pdf_path):
                        errors.append({"scan_id": sid, "error": "report not generated or not found"})
                        continue

                    dest_name = f"scan_{sid}_report.pdf"
                    dest_path = os.path.join(tmpdir, dest_name)
                    shutil.copy(pdf_path, dest_path)
                    pdf_paths.append(dest_path)
                except Exception as e:
                    logger.exception("Failed generating report for scan %s", sid)
                    errors.append({"scan_id": sid, "error": str(e)})

            if len(pdf_paths) == 0:
                return jsonify({"error": "No reports generated", "details": errors}), 500

            zip_base = os.path.join(tmpdir, "reports_bundle")
            zip_path = shutil.make_archive(zip_base, 'zip', tmpdir)

            @after_this_request
            def cleanup(response):
                try:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass
                return response

            return send_file(
                zip_path,
                as_attachment=True,
                download_name=f"scan_reports_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mimetype='application/zip'
            )
        except Exception as e:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass
            logger.exception("Bulk report generation failed")
            return jsonify({"error": "Bulk report generation failed", "detail": str(e)}), 500

    # ================= SETTINGS ENDPOINTS =================
    @app.route('/api/settings/general', methods=['GET', 'PUT'])
    @role_required(["Admin"])
    def general_settings():
        if request.method == 'GET':
            return jsonify({
                'app_name': 'Aegis Security Platform',
                'version': '1.0.0',
                'scan_retention_days': 90,
                'auto_scan_enabled': False,
                'max_concurrent_scans': 3,
                'default_scan_mode': 'medium'
            })
        else:
            data = request.get_json(silent=True) or {}
            return jsonify({'message': 'Settings updated successfully', 'data': data})

    @app.route('/api/settings/users', methods=['GET'])
    @role_required(["Admin"])
    def get_users():
        users = User.query.all()
        return jsonify([{
            'id': u.id,
            'username': u.username,
            'email': getattr(u, 'email', ''),
            'role': u.role,
            'created_at': u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None
        } for u in users])

    @app.route('/api/settings/users/<int:user_id>/role', methods=['PUT'])
    @role_required(["Admin"])
    def update_user_role(user_id):
        data = request.get_json(silent=True) or {}
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.role = data.get('role', user.role)
        db.session.commit()
        return jsonify({'message': f'User {user.username} role updated to {user.role}'})

    @app.route('/api/settings/security', methods=['GET', 'PUT'])
    @role_required(["Admin"])
    def security_settings():
        if request.method == 'GET':
            return jsonify({
                'password_min_length': 8,
                'session_timeout_minutes': 60,
                'mfa_enabled': False,
                'api_rate_limit': 100
            })
        else:
            data = request.get_json(silent=True) or {}
            return jsonify({'message': 'Security settings updated', 'data': data})

    @app.route('/api/settings/notifications', methods=['GET', 'PUT'])
    @role_required(["Admin"])
    def notification_settings():
        if request.method == 'GET':
            return jsonify({
                'email_enabled': False,
                'email_server': '',
                'slack_enabled': False,
                'slack_webhook': '',
                'notify_on_critical': True,
                'notify_on_scan_complete': False
            })
        else:
            data = request.get_json(silent=True) or {}
            return jsonify({'message': 'Notification settings updated', 'data': data})

    @app.route('/api/settings/api-keys', methods=['GET', 'POST', 'DELETE'])
    @role_required(["Admin"])
    def api_keys():
        if request.method == 'GET':
            return jsonify({'keys': []})
        elif request.method == 'POST':
            import secrets
            new_key = secrets.token_urlsafe(32)
            return jsonify({'key': new_key, 'message': 'API key generated'})
        else:
            return jsonify({'message': 'API key deleted'})

    # ================= HEALTH CHECK =================
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({'status': 'ok', 'time': datetime.datetime.now(datetime.timezone.utc).isoformat()}), 200

    return app, socketio


if __name__ == '__main__':
    app, socketio = create_app()
    with app.app_context():
        db.create_all()

        # Ensure log_data column exists (SQLite ALTER TABLE)
        try:
            db.session.execute(db.text("SELECT log_data FROM scan LIMIT 1"))
        except Exception:
            try:
                db.session.execute(db.text("ALTER TABLE scan ADD COLUMN log_data TEXT"))
                db.session.commit()
                logger.info("Added log_data column to scan table")
            except Exception as e:
                logger.debug(f"log_data column might already exist: {e}")

        if app.config.get('ENV', 'development') == 'development' and not User.query.filter_by(username='admin').first():
            print("Creating default admin (admin/admin)")
            admin_user = User(username='admin', role=ROLE_ADMIN)
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()

    host = os.environ.get('APP_HOST', '0.0.0.0')
    port = int(os.environ.get('APP_PORT', 5000))
    
    # Run with SocketIO
    socketio.run(app, host=host, port=port, debug=True, allow_unsafe_werkzeug=True)
