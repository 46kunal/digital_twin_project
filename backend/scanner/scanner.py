# scanner.py

"""
Scanner orchestrator (XML-based)
- Runs nmap via scanner.nmap_runner (which returns XML on stdout)
- Captures stderr lines into Scan.log (live) using a thread-safe flusher
- Persists Scan, VM and Vulnerability rows via writer.write_host_and_vulns
- Supports CLI: python -m scanner.scanner --target --mode fast|medium|full --no-parse
"""

import datetime as _dt
import ipaddress
import threading
import queue
from typing import Optional, List, Dict, Any

# relative imports to other modules in the scanner package
from scanner.nmap_runner import build_nmap_cmd, run_nmap_and_capture_xml
from scanner.xml_parser import parse_nmap_xml
from scanner.cve_parser import extract_cves_from_text
from scanner.writer import write_host_and_vulns

# models (project-level module; keep absolute import)
from models import Scan, db

# Use sessionmaker for flusher thread DB sessions
from sqlalchemy.orm import sessionmaker

# Simple numeric estimate mapping (seconds per host). Use these to compute ETA timestamp.
_MODE_ESTIMATE_SECONDS = {
    "fast": 120,    # 2 minutes
    "medium": 360,  # 6 minutes
    "full": 900     # 15 minutes
}


def classify_risk_from_script(sid: str, out: str):
    """
    Very simple ISO 27005 style risk classification:
    - Decide likelihood and impact from the script output
    - Compute risk_score = likelihood_score * impact_score  (1-25)
    """
    text = (out or "").lower()
    sid_lower = sid.lower()

    # Example heuristic rules - you can tweak these anytime
    if "remote code execution" in text or "exec arbitrary code" in text:
        likelihood = "High"
        impact = "High"
    elif "authentication bypass" in text or "default credentials" in text or "anonymous login" in text:
        likelihood = "High"
        impact = "Medium"
    elif "privilege escalation" in text:
        likelihood = "Medium"
        impact = "High"
    elif "information disclosure" in text or "sensitive information" in text:
        likelihood = "Medium"
        impact = "Medium"
    elif "weak cipher" in text or "ssl" in sid_lower or "tls" in sid_lower:
        likelihood = "Medium"
        impact = "Low"
    else:
        # fallback for generic findings
        likelihood = "Medium"
        impact = "Medium"

    scale = {"Low": 1, "Medium": 3, "High": 5}
    risk_score = scale[likelihood] * scale[impact]  # 1–25

    return likelihood, impact, risk_score


def emit_progress(scan_id, progress, phase, message='', eta=None):
    """Emit real-time scan progress via SocketIO"""
    try:
        from flask import current_app
        socketio = current_app.socketio
        
        # Update database
        try:
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.progress = progress
                scan.phase = phase
                scan.status = 'running' if progress < 100 else 'completed'
                if eta:
                    scan.eta = eta
                
                # Append to log_data
                timestamp = _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                log_entry = f"[{timestamp}] [{phase}] {progress}% - {message}"
                if hasattr(scan, 'log_data') and scan.log_data:
                    scan.log_data = scan.log_data + '\n' + log_entry
                else:
                    scan.log_data = log_entry
                
                db.session.commit()
        except Exception:
            pass
        
        # Emit WebSocket event
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': progress,
            'phase': phase,
            'status': 'running' if progress < 100 else 'completed',
            'message': message,
            'eta': eta or '',
            'timestamp': _dt.datetime.now(_dt.timezone.utc).isoformat()
        })
        
        # Also emit legacy event for compatibility
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'status': 'running' if progress < 100 else 'completed',
            'progress': progress,
            'phase': phase
        })
        
        print(f"✅ Emitted: Scan {scan_id} - {progress}% - {phase}")
        
    except Exception as e:
        print(f"❌ Failed to emit progress: {e}")


# Bounded queue for stderr lines (thread-safe)
_stderr_queue = queue.Queue(maxsize=5000)


def validate_target(target: str) -> bool:
    """
    Accept single IP or CIDR or simple hostname. Reject other shells/commands.
    """
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    
    # allow IP or CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except Exception:
        # allow simple hostname (letters, digits, hyphen, dot)
        import re
        if re.match(r'^[A-Za-z0-9\-\._]+$', target):
            return True
    
    return False


def _enqueue_stderr_line(line: str):
    """
    Non-blocking enqueue of stderr lines. If queue full, drop oldest to make room.
    This function is safe to call from the stderr reader thread.
    """
    try:
        _stderr_queue.put_nowait(line)
    except queue.Full:
        try:
            _stderr_queue.get_nowait()  # drop oldest
        except Exception:
            pass
        try:
            _stderr_queue.put_nowait(line)
        except Exception:
            # Last resort: drop the line silently
            pass


def _start_stderr_flusher(scan_id: int) -> threading.Thread:
    """
    Start a daemon flusher thread that consumes _stderr_queue and writes to DB.
    Each flusher uses its own SQLAlchemy Session (sessionmaker bound to db.engine).
    The flusher exits when it detects the Scan row status is completed/failed and the queue is drained.
    """
    Session = sessionmaker(bind=db.engine)
    
    def _flusher():
        session = Session()
        try:
            while True:
                try:
                    line = _stderr_queue.get(timeout=1.0)
                except queue.Empty:
                    # If queue empty, check if scan finished; if so, exit loop.
                    try:
                        s = session.get(Scan, scan_id)
                        if s is None or (s.status in ("completed", "failed") and _stderr_queue.empty()):
                            break
                        else:
                            continue
                    except Exception:
                        # DB trouble: keep trying until queue drained and scan finished in main thread
                        continue
                
                # persist the line safely (session local to this thread)
                try:
                    s = session.get(Scan, scan_id)
                    if s:
                        # append with timestamp; keep growth reasonable
                        timestamp_line = f"[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {line}"
                        if hasattr(s, 'log_data'):
                            s.log_data = (s.log_data or "") + "\n" + timestamp_line
                        if hasattr(s, 'log'):
                            s.log = (s.log or "") + "\n" + timestamp_line
                        try:
                            session.commit()
                        except Exception:
                            try:
                                session.rollback()
                            except Exception:
                                pass
                except Exception:
                    try:
                        session.rollback()
                    except Exception:
                        pass
                    # swallow errors and continue draining
                    continue
        finally:
            try:
                session.close()
            except Exception:
                pass
    
    th = threading.Thread(target=_flusher, daemon=True)
    th.start()
    return th


def run_scan(scan_id_or_target, target=None, mode: str = "fast", parse_xml: bool = True):
    """
    Orchestrator with real-time progress tracking.
    - run_scan(scan_id, target, mode="fast", parse_xml=True) (app mode)
    - run_scan("1.2.3.4", None, mode="fast", parse_xml=True) (legacy CLI)
    
    mode: "fast" | "medium" | "full"
    parse_xml: whether to parse the XML and create VM/Vulnerability rows.
    """
    # detect legacy usage (if only target string provided)
    if target is None and isinstance(scan_id_or_target, str):
        real_target = scan_id_or_target
        scan = None
    else:
        scan_id = int(scan_id_or_target) if scan_id_or_target is not None else None
        real_target = target
        scan = None
    
    # validate target early
    if not validate_target(real_target):
        raise ValueError(f"Invalid target: {real_target}")
    
    # try to get an app context (create_app) to bind DB if available
    try:
        from app import create_app
        app, _ = create_app()
        ctx = app.app_context()
        ctx.push()
    except Exception:
        app = None
        ctx = None
    
    # fetch existing scan if provided
    if 'scan_id' in locals() and scan_id is not None:
        try:
            scan = db.session.get(Scan, scan_id)
        except Exception:
            scan = None
    
    # create scan row if needed
    if not scan:
        try:
            scan = Scan(
                target=real_target,
                status="running",
                start_time=_dt.datetime.now(_dt.timezone.utc),
                progress=0,
                phase="initializing",
                log="",
                log_data="",
                eta=""
            )
            db.session.add(scan)
            db.session.commit()
            scan_id = scan.id
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            scan = None
    
    # Phase 0: Initializing (0%)
    if scan:
        emit_progress(scan.id, 0, 'initializing', 'Starting vulnerability scan...')
    
    # update initial scan row (set ETA hint as an ISO timestamp if possible)
    if scan:
        try:
            db.session.refresh(scan)
        except Exception:
            pass
        
        scan.status = "running"
        scan.start_time = _dt.datetime.now(_dt.timezone.utc)
        scan.phase = "preparing"
        
        # compute initial ETA
        per_host_secs = _MODE_ESTIMATE_SECONDS.get(mode, 120)
        try:
            scan.eta = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=per_host_secs)).isoformat()
        except Exception:
            scan.eta = ""
        
        try:
            log_msg = f"Scan started (mode={mode}, target={real_target})"
            if hasattr(scan, 'log_data'):
                scan.log_data = (scan.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {log_msg}"
            if hasattr(scan, 'log'):
                scan.log = (scan.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {log_msg}"
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
    
    # Phase 1: Preparing (5%)
    if scan:
        emit_progress(scan.id, 5, 'preparing', 'Preparing nmap command...', scan.eta)
    
    # build nmap command
    cmd = build_nmap_cmd(real_target, mode=mode)
    
    # Phase 2: Port Scanning (10%)
    if scan:
        emit_progress(scan.id, 10, 'port_scanning', f'Scanning target {real_target}...', scan.eta)
    
    # Start flusher thread to safely accept stderr lines
    flusher_thread = None
    if scan:
        flusher_thread = _start_stderr_flusher(scan.id)
    
    # Run nmap; pass enqueue function as stderr callback
    rc, xml_out, stderr_tail = run_nmap_and_capture_xml(cmd, stderr_line_cb=_enqueue_stderr_line, timeout=None)
    
    # Phase 3: Analyzing (50%)
    if scan:
        emit_progress(scan.id, 50, 'analyzing', 'Analyzing scan results...')
    
    # After runner returns: final drain of queued stderr lines into DB
    if scan:
        try:
            Session = sessionmaker(bind=db.engine)
            session = Session()
            try:
                while not _stderr_queue.empty():
                    try:
                        line = _stderr_queue.get_nowait()
                    except queue.Empty:
                        break
                    
                    try:
                        s = session.get(Scan, scan.id)
                        if s:
                            timestamp_line = f"[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {line}"
                            if hasattr(s, 'log_data'):
                                s.log_data = (s.log_data or "") + "\n" + timestamp_line
                            if hasattr(s, 'log'):
                                s.log = (s.log or "") + "\n" + timestamp_line
                            try:
                                session.commit()
                            except Exception:
                                try:
                                    session.rollback()
                                except Exception:
                                    pass
                    except Exception:
                        try:
                            session.rollback()
                        except Exception:
                            pass
                        continue
            finally:
                try:
                    session.close()
                except Exception:
                    pass
        except Exception:
            pass
    
    # store raw XML on Scan
    if scan:
        try:
            s = db.session.get(Scan, scan.id) or scan
            s.raw_output = xml_out
            try:
                db.session.commit()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
    
    # record nmap return code
    if scan:
        try:
            s = db.session.get(Scan, scan.id) or scan
            log_msg = f"nmap rc={rc}"
            if hasattr(s, 'log_data'):
                s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {log_msg}"
            if hasattr(s, 'log'):
                s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {log_msg}"
            try:
                db.session.commit()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
    
    # handle nmap failure
    if rc != 0 and not xml_out:
        if scan:
            try:
                s = db.session.get(Scan, scan.id) or scan
                s.status = "failed"
                s.phase = "nmap_failed"
                s.progress = 100
                error_msg = f"nmap failed: {stderr_tail}"
                if hasattr(s, 'log_data'):
                    s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                if hasattr(s, 'log'):
                    s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                emit_progress(scan.id, 100, 'failed', error_msg)
                try:
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        
        if ctx:
            try:
                ctx.pop()
            except Exception:
                pass
        
        if flusher_thread:
            try:
                flusher_thread.join(timeout=2)
            except Exception:
                pass
        
        return
    
    # Phase 4: Parsing (60%)
    hosts: List[Dict[str, Any]] = []
    if xml_out:
        if scan:
            emit_progress(scan.id, 60, 'parsing', 'Parsing XML results...')
        
        try:
            hosts = parse_nmap_xml(xml_out)
        except Exception as e:
            if scan:
                try:
                    s = db.session.get(Scan, scan.id) or scan
                    error_msg = f"XML parse error: {e}"
                    if hasattr(s, 'log_data'):
                        s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                    if hasattr(s, 'log'):
                        s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                    try:
                        db.session.commit()
                    except Exception:
                        try:
                            db.session.rollback()
                        except Exception:
                            pass
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            hosts = []
    
    # If parse_xml is False: minimal VM upsert then exit
    if not parse_xml:
        if hosts:
            try:
                from models import VM
                for host in hosts:
                    ip = host.get("ip") or host.get("hostname")
                    if not ip:
                        continue
                    
                    try:
                        vm = VM.query.filter_by(ip_address=str(ip)).first()
                    except Exception:
                        try:
                            vm = db.session.query(VM).filter_by(ip_address=str(ip)).first()
                        except Exception:
                            vm = None
                    
                    if not vm:
                        vm = VM(ip_address=str(ip), hostname=host.get("hostname") or "Unknown")
                        db.session.add(vm)
                
                try:
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        
        if scan:
            try:
                s = db.session.get(Scan, scan.id) or scan
                s.status = "completed" if rc == 0 else "failed"
                s.phase = "completed" if rc == 0 else s.phase
                s.progress = 100
                s.end_time = _dt.datetime.now(_dt.timezone.utc)
                emit_progress(scan.id, 100, 'completed', 'Scan completed')
                try:
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        
        if flusher_thread:
            try:
                flusher_thread.join(timeout=2)
            except Exception:
                pass
        
        if ctx:
            try:
                ctx.pop()
            except Exception:
                pass
        
        return
    
    # if no hosts found
    if not hosts:
        if scan:
            try:
                s = db.session.get(Scan, scan.id) or scan
                s.status = "completed"
                s.progress = 100
                s.phase = "no_hosts"
                msg = "No hosts found"
                if hasattr(s, 'log_data'):
                    s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                if hasattr(s, 'log'):
                    s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                emit_progress(scan.id, 100, 'completed', msg)
                try:
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        
        if flusher_thread:
            try:
                flusher_thread.join(timeout=2)
            except Exception:
                pass
        
        if ctx:
            try:
                ctx.pop()
            except Exception:
                pass
        
        return
    
    # Phase 5: Vulnerability Detection (70-85%)
    if scan:
        emit_progress(scan.id, 70, 'vulnerability_detection', f'Processing {len(hosts)} hosts...')
    
    total_hosts = max(1, len(hosts))
    host_idx = 0
    
    for host in hosts:
        host_idx += 1
        if scan:
            try:
                s = db.session.get(Scan, scan.id) or scan
                pct_est = 70 + int((host_idx / total_hosts) * 15)  # 70-85%
                s.progress = pct_est
                s.phase = "processing_host"
                host_ip = host.get('ip', 'unknown')
                msg = f"Processing host {host_ip}"
                if hasattr(s, 'log_data'):
                    s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                if hasattr(s, 'log'):
                    s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                emit_progress(scan.id, pct_est, 'analyzing_vulnerabilities', msg)
                
                # update ETA
                try:
                    per_host = _MODE_ESTIMATE_SECONDS.get(mode, 120)
                    remaining_hosts = max(0, total_hosts - host_idx)
                    remaining_secs = remaining_hosts * per_host
                    
                    if remaining_secs > 0:
                        eta_dt = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=remaining_secs)
                        s.eta = eta_dt.isoformat()
                    else:
                        s.eta = ""
                    
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        
        # collect parsed vulns for each port (ISO 27005 style risk, no CVEs)
        parsed_vulns_for_port: Dict[int, List[Dict[str, Any]]] = {}

        for p in host.get("ports", []):
            scripts = p.get("scripts", {}) or {}
            portnum = p.get("port")
            if portnum is None:
                continue

            findings: List[Dict[str, Any]] = []

            for sid, out in scripts.items():
                # only consider non-empty script output
                if not isinstance(out, str) or not out.strip():
                    continue

                likelihood, impact, risk_score = classify_risk_from_script(sid, out)

                findings.append({
                    "issue_id": sid,                          # Nmap script id
                    "likelihood": likelihood,                 # "Low"/"Medium"/"High"
                    "impact": impact,                         # "Low"/"Medium"/"High"
                    "risk_score": risk_score,                 # 1-25
                    "description": f"[{sid}] {out[:500]}",    # trim long text for DB
                })

            if findings:
                parsed_vulns_for_port[int(portnum)] = findings

        # write host + vulnerability rows
        try:
            write_host_and_vulns(scan, host, parsed_vulns_for_port)
        except Exception as e:
            if scan:
                try:
                    s = db.session.get(Scan, scan.id) or scan
                    error_msg = f"writer error: {e}"
                    if hasattr(s, 'log_data'):
                        s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                    if hasattr(s, 'log'):
                        s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {error_msg}"
                    try:
                        db.session.commit()
                    except Exception:
                        try:
                            db.session.rollback()
                        except Exception:
                            pass
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
        
        if scan:
            try:
                s = db.session.get(Scan, scan.id) or scan
                msg = f"Finished host {host_ip}"
                if hasattr(s, 'log_data'):
                    s.log_data = (s.log_data or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                if hasattr(s, 'log'):
                    s.log = (s.log or "") + f"\n[{_dt.datetime.now(_dt.timezone.utc).isoformat()}] {msg}"
                try:
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
    
    # Phase 6: Finalizing (90%)
    if scan:
        emit_progress(scan.id, 90, 'finalizing', 'Saving final results...')
    
    # Phase 7: Complete (100%)
    if scan:
        try:
            s = db.session.get(Scan, scan.id) or scan
            s.status = "completed"
            s.phase = "completed"
            s.progress = 100
            s.end_time = _dt.datetime.now(_dt.timezone.utc)
            s.eta = ""
            emit_progress(scan.id, 100, 'completed', 'Scan completed successfully')
            try:
                db.session.commit()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
    
    # cleanup
    if flusher_thread:
        try:
            flusher_thread.join(timeout=3)
        except Exception:
            pass
    
    if ctx:
        try:
            ctx.pop()
        except Exception:
            pass
    
    return


# -------------------------
# CLI entrypoint
# -------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Standalone scanner runner")
    parser.add_argument("--target", required=True, help="Target IP or CIDR")
    parser.add_argument("--mode", choices=["fast", "medium", "full"], default="fast",
                        help="Scan mode: fast=top ports (-F), medium=top-1000, full=all ports (-p-)")
    parser.add_argument("--scan_id", type=int, required=False, help="Optional existing scan_id (app mode)")
    parser.add_argument("--no-parse", action="store_true", help="Save raw XML only; do not parse ports/vulns")
    args = parser.parse_args()
    
    parse_flag = not args.no_parse
    
    # Call run_scan with consistent signature
    if args.scan_id:
        run_scan(args.scan_id, args.target, mode=args.mode, parse_xml=parse_flag)
    else:
        run_scan(args.target, None, mode=args.mode, parse_xml=parse_flag)


if __name__ == "__main__":
    main()
