# api/vm_routes.py
import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from functools import wraps

logger = logging.getLogger("digital_twin_app.vms")
vm_bp = Blueprint("vm", __name__)


def role_required(roles):
    if isinstance(roles, str):
        allowed = [roles]
    else:
        allowed = list(roles)

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


def _models():
    from models import db, VM
    return db, VM


# List / Read
@vm_bp.route("/vm", methods=["GET"])
@vm_bp.route("/vms", methods=["GET"])
@role_required(["Viewer", "Analyst", "Admin"])
def list_vms():
    try:
        db, VM = _models()
        vms = VM.query.all()
        out = []
        for v in vms:
            out.append({
                "id": v.id,
                "ip": v.ip_address,        # Fixed: use ip_address
                "name": v.hostname,        # Fixed: use hostname
                "os": v.os or "Unknown",
                "status": "active"         # Hardcoded or add to model
            })
        return jsonify({"vms": out}), 200
    except Exception:
        logger.exception("list_vms failed")
        return jsonify({"error": "could not fetch VMs"}), 500


@vm_bp.route("/vm/<int:vm_id>", methods=["GET"])
@role_required(["Viewer", "Analyst", "Admin"])
def get_vm(vm_id):
    try:
        db, VM = _models()
        v = VM.query.get(vm_id)
        if not v:
            return jsonify({"error": "VM not found"}), 404
        return jsonify({
            "id": v.id,
            "ip": v.ip_address,
            "name": v.hostname,
            "os": v.os or "Unknown",
            "status": "active"
        }), 200
    except Exception:
        logger.exception("get_vm failed for id=%s", vm_id)
        return jsonify({"error": "could not fetch VM"}), 500


# Create
@vm_bp.route("/vm", methods=["POST"])
@role_required(["Analyst", "Admin"])
def create_vm():
    data = request.get_json() or {}
    ip = data.get("ip")
    name = data.get("name")
    
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    try:
        db, VM = _models()
        new_vm = VM(
            ip_address=ip,
            hostname=name or "Unknown"
        )
        if "os" in data:
            new_vm.os = data.get("os")
        
        db.session.add(new_vm)
        db.session.commit()
        return jsonify({"message": "vm created", "id": new_vm.id}), 201
    except Exception:
        logger.exception("create_vm failed with data=%s", data)
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({"error": "could not create VM"}), 500


# Update
@vm_bp.route("/vm/<int:vm_id>", methods=["PUT", "PATCH"])
@role_required(["Analyst", "Admin"])
def update_vm(vm_id):
    data = request.get_json() or {}
    try:
        db, VM = _models()
        v = VM.query.get(vm_id)
        if not v:
            return jsonify({"error": "VM not found"}), 404
        
        if "ip" in data:
            v.ip_address = data.get("ip")
        if "name" in data:
            v.hostname = data.get("name")
        if "os" in data:
            v.os = data.get("os")
        
        db.session.commit()
        return jsonify({"message": "vm updated"}), 200
    except Exception:
        logger.exception("update_vm failed for id=%s data=%s", vm_id, data)
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({"error": "could not update VM"}), 500


# Delete
@vm_bp.route("/vm/<int:vm_id>", methods=["DELETE"])
@role_required(["Admin"])
def delete_vm(vm_id):
    try:
        db, VM = _models()
        v = VM.query.get(vm_id)
        if not v:
            return jsonify({"error": "VM not found"}), 404
        
        db.session.delete(v)
        db.session.commit()
        return jsonify({"message": "vm deleted"}), 200
    except Exception:
        logger.exception("delete_vm failed for id=%s", vm_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({"error": "could not delete VM"}), 500
