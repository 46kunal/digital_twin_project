# auth.py

from flask import Blueprint, request, jsonify
from models import db, User, RevokedToken, ROLE_VIEWER
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt,
    set_refresh_cookies, unset_jwt_cookies
)
from datetime import timedelta

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    role = data.get("role", ROLE_VIEWER)
    
    if not username or not password:
        return jsonify({"msg": "username and password required"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "username exists"}), 400
    
    u = User(username=username, email=email, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    
    return jsonify({"msg": "user created", "user": u.to_dict()}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"msg": "username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "invalid credentials"}), 401
    
    if not user.is_active:
        return jsonify({"msg": "user disabled"}), 403

    additional_claims = {"role": user.role}
    access_token = create_access_token(
        identity=user.username,
        additional_claims=additional_claims,
        expires_delta=timedelta(hours=8)
    )
    refresh_token = create_refresh_token(
        identity=user.username,
        additional_claims=additional_claims,
        expires_delta=timedelta(days=7)
    )

    resp = jsonify({"access_token": access_token, "user": user.to_dict()})
    set_refresh_cookies(resp, refresh_token)
    return resp, 200

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True, locations=["cookies"])
def refresh():
    current_jwt = get_jwt()
    identity = get_jwt_identity()
    role = current_jwt.get("role")
    old_jti = current_jwt.get("jti")

    # Revoke old refresh token
    if old_jti:
        RevokedToken.add(old_jti, token_type="refresh")

    # Issue new tokens
    additional_claims = {"role": role} if role else {}
    new_access = create_access_token(
        identity=identity,
        additional_claims=additional_claims,
        expires_delta=timedelta(hours=8)
    )
    new_refresh = create_refresh_token(
        identity=identity,
        additional_claims=additional_claims,
        expires_delta=timedelta(days=7)
    )

    resp = jsonify({"access_token": new_access})
    set_refresh_cookies(resp, new_refresh)
    return resp, 200

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    access_jti = get_jwt().get("jti")
    if access_jti:
        RevokedToken.add(access_jti, token_type="access")
    
    resp = jsonify({"msg": "logged out"})
    unset_jwt_cookies(resp)
    return resp, 200

@auth_bp.route("/logout_refresh", methods=["POST"])
@jwt_required(refresh=True, locations=["cookies"])
def logout_refresh():
    jti = get_jwt().get("jti")
    if jti:
        RevokedToken.add(jti, token_type="refresh")
    
    resp = jsonify({"msg": "refresh token revoked and cookie cleared"})
    unset_jwt_cookies(resp)
    return resp, 200

@auth_bp.route("/whoami", methods=["GET"])
@jwt_required()
def whoami():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "not found"}), 404
    
    return jsonify({"user": user.to_dict()}), 200
