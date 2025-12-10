import logging
import re
from typing import Dict, Any, List, Optional
from collections import deque
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from models import db, VM, Vulnerability, Scan

logger = logging.getLogger("scanner.writer")


def _sanitize_text(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    # remove control chars, collapse whitespace, limit size
    s = re.sub(r'[\x00-\x1f\x7f]', ' ', s)
    s = " ".join(s.split())
    return s.strip()[:2000]


def _safe_commit():
    try:
        db.session.commit()
        return True
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.warning("[writer] DB commit failed: %s", e)
        return False


def _risk_to_severity(score):
    """
    Map numeric risk_score (1-25) to severity band.
    You can tune these thresholds to match your risk appetite.
    """
    try:
        if score is None:
            return "Unknown"
        s = int(score)
        if s >= 20:
            return "Critical"
        if s >= 12:
            return "High"
        if s >= 6:
            return "Medium"
        if s > 0:
            return "Low"
    except Exception:
        pass
    return "Unknown"


def write_host_and_vulns(scan: Optional[Scan],
                         host: Dict[str, Any],
                         parsed_vulns_for_port: Dict[int, List[Dict[str, Any]]]):
    """
    Persist a host (VM) and its vulnerabilities.

    parsed_vulns_for_port: mapping port (int) -> list of dicts containing keys:
        'issue_id', 'risk_score', 'likelihood', 'impact', 'description'
    """
    ip = host.get("ip") or host.get("hostname")
    if not ip:
        logger.debug("Skipping host with no ip/hostname: %r", host)
        return
    ip = str(ip)

    hostname = _sanitize_text(host.get("hostname")) or "Unknown"

    try:
        vm = VM.query.filter_by(ip_address=ip).first()
    except Exception as e:
        logger.exception("DB query for VM failed for %s: %s", ip, e)
        vm = None

    if not vm:
        vm = VM(ip_address=ip, hostname=hostname)
        db.session.add(vm)
        try:
            # flush to obtain vm.id; handle race on unique ip_address
            db.session.flush()
        except IntegrityError:
            try:
                db.session.rollback()
            except Exception:
                pass
            try:
                vm = VM.query.filter_by(ip_address=ip).first()
            except Exception as e:
                logger.exception("Fallback VM query failed for %s: %s", ip, e)
                vm = None
            if not vm:
                # Last-ditch: re-create and commit
                vm = VM(ip_address=ip, hostname=hostname)
                db.session.add(vm)
                if not _safe_commit():
                    logger.error("Failed to create VM for %s after race handling", ip)
                    return
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            logger.exception("Error creating VM %s: %s", ip, e)
            return
        else:
            # If flush succeeded, commit to persist the VM (so vm.id is stable across sessions)
            _safe_commit()
    else:
        # update hostname if improved
        if hostname and vm.hostname != hostname:
            vm.hostname = hostname
            _safe_commit()

    # update OS if present
    os_val = host.get("os")
    if os_val:
        vm.os = _sanitize_text(os_val)
        _safe_commit()

    ports = host.get("ports", []) or []
    for p in ports:
        state = p.get("state", "unknown")
        if str(state).lower() != "open":
            continue

        portnum = p.get("port")
        try:
            # normalize port to int and skip invalid
            portnum = int(portnum)
        except Exception:
            logger.debug("Skipping invalid port value for host %s: %r", ip, p.get("port"))
            continue

        svc = p.get("service", {}) or {}
        service_name = _sanitize_text(svc.get("name") or "unknown")
        product = _sanitize_text(svc.get("product") or "")
        version = _sanitize_text(svc.get("version") or product or "")
        cpe_val = _sanitize_text(svc.get("cpe")) if isinstance(svc.get("cpe"), str) else None

        parsed = parsed_vulns_for_port.get(portnum) or []
        if parsed:
            for v in parsed:
                # be defensive about parsed vuln shape
                if not isinstance(v, dict):
                    logger.debug("Skipping malformed parsed vuln for %s:%s: %r", ip, portnum, v)
                    continue

                risk_score = v.get("risk_score")
                likelihood = v.get("likelihood")
                impact = v.get("impact")
                severity = _risk_to_severity(risk_score)

                try:
                    new_v = Vulnerability(
                        vm_id=vm.id,
                        scan_id=scan.id if scan else None,
                        port=portnum,
                        service=service_name,
                        version=version or None,
                        cpe=cpe_val,
                        issue_id=_sanitize_text(v.get("issue_id")) if v.get("issue_id") else None,
                        risk_score=risk_score,
                        likelihood=_sanitize_text(likelihood) if likelihood else None,
                        impact=_sanitize_text(impact) if impact else None,
                        severity=severity,
                        description=_sanitize_text(v.get("description")),
                    )
                    db.session.add(new_v)
                    try:
                        db.session.flush()
                    except IntegrityError:
                        db.session.rollback()
                        logger.warning(
                            "Duplicate/Integrity error inserting vuln for %s:%s %s",
                            ip, portnum, v.get("issue_id")
                        )
                        continue
                    except Exception as e:
                        db.session.rollback()
                        logger.exception("Error flushing vuln for %s:%s : %s", ip, portnum, e)
                        continue

                    # commit each vuln to prevent one bad row aborting host processing
                    if not _safe_commit():
                        # commit failed; continue with next vuln
                        continue
                except Exception as e:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
                    logger.exception("Failed to create vulnerability row for %s:%s: %s", ip, portnum, e)
                    continue
        else:
            # no parsed findings for this open port: record a generic "open port" issue
            try:
                generic_desc = f"Open port {portnum}/{service_name}"
                generic_risk = None
                new_v = Vulnerability(
                    vm_id=vm.id,
                    scan_id=scan.id if scan else None,
                    port=portnum,
                    service=service_name,
                    version=version or None,
                    cpe=cpe_val,
                    issue_id=None,
                    risk_score=generic_risk,
                    likelihood=None,
                    impact=None,
                    severity="Unknown",
                    description=generic_desc,
                )
                db.session.add(new_v)
                if not _safe_commit():
                    logger.warning("Failed to commit open-port vuln for %s:%s", ip, portnum)
                    continue
            except Exception as e:
                try:
                    db.session.rollback()
                except Exception:
                    pass
                logger.exception("Failed to create open-port row for %s:%s: %s", ip, portnum, e)
                continue
