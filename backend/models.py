import datetime
from flask_sqlalchemy import SQLAlchemy
import bcrypt as bcrypt_lib

db = SQLAlchemy()

ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Analyst"
ROLE_VIEWER = "Viewer"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), default=ROLE_VIEWER, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def set_password(self, raw_password: str) -> None:
        """Hash password using native bcrypt (Python 3.13 compatible)."""
        salt = bcrypt_lib.gensalt()
        self.password_hash = bcrypt_lib.hashpw(
            raw_password.encode("utf-8"), salt
        ).decode("utf-8")

    def check_password(self, raw_password: str) -> bool:
        """Verify password using native bcrypt."""
        if not self.password_hash:
            return False
        return bcrypt_lib.checkpw(
            raw_password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RevokedToken(db.Model):
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(128), nullable=False, unique=True, index=True)
    token_type = db.Column(db.String(32), nullable=False)
    revoked_at = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    @classmethod
    def add(cls, jti: str, token_type: str) -> bool:
        if not cls.query.filter_by(jti=jti).first():
            r = cls(jti=jti, token_type=token_type)
            db.session.add(r)
            db.session.commit()
            return True
        return False

    @classmethod
    def is_revoked(cls, jti: str) -> bool:
        return cls.query.filter_by(jti=jti).first() is not None


class Scan(db.Model):
    __tablename__ = "scan"

    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="pending", index=True)
    target = db.Column(db.String(255), nullable=False, index=True)
    progress = db.Column(db.Integer, default=0)
    phase = db.Column(db.String(80), default="initializing")
    eta = db.Column(db.String(32), default="")
    log = db.Column(db.Text, default="")
    raw_output = db.Column(db.Text, nullable=True)

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class VM(db.Model):
    __tablename__ = "vm"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255))
    os = db.Column(db.String(255))

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="vm",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class Vulnerability(db.Model):
    __tablename__ = "vulnerability"

    id = db.Column(db.Integer, primary_key=True)

    vm_id = db.Column(db.Integer, db.ForeignKey("vm.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)

    port = db.Column(db.Integer, nullable=True, index=True)
    service = db.Column(db.String(50), nullable=True)
    version = db.Column(db.String(50), nullable=True)

    # Risk-based fields (ISO 27005 style)
    issue_id = db.Column(db.String(128), nullable=True, index=True)  # e.g. nmap script id
    risk_score = db.Column(db.Integer, nullable=True, index=True)    # 1–25 from likelihood * impact
    likelihood = db.Column(db.String(16), nullable=True)             # Low / Medium / High
    impact = db.Column(db.String(16), nullable=True)                 # Low / Medium / High
    severity = db.Column(db.String(20), nullable=True, index=True)   # mapped from risk_score

    status = db.Column(db.String(20), default="open")  # open/closed for the vuln itself

    # Legacy CVE/CVSS fields (kept for backward compatibility; may be empty)
    cve_id = db.Column(db.String(64), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)

    description = db.Column(db.Text, nullable=True)
    cpe = db.Column(db.String(255), nullable=True)

    created_at = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Remediation tracking
    remediation_status = db.Column(
        db.String(20), default="open"
    )  # open, in_progress, resolved, false_positive
    assigned_to = db.Column(db.String(128), nullable=True)
    remediation_notes = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
