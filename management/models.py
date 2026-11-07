"""Sentinel Management - SQLAlchemy models for CS Department dashboard."""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="cs_viewer")  # cs_admin, cs_analyst, cs_viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(128), nullable=False)
    os_platform = db.Column(db.String(32), default="Windows")
    agent_version = db.Column(db.String(32), default="1.0.0")
    api_key = db.Column(db.String(128), nullable=False)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    total_scans = db.Column(db.Integer, default=0)
    total_threats = db.Column(db.Integer, default=0)
    total_quarantined = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os_platform": self.os_platform,
            "agent_version": self.agent_version,
            "is_online": self.is_online,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_scans": self.total_scans,
            "total_threats": self.total_threats,
            "total_quarantined": self.total_quarantined,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), db.ForeignKey("agents.agent_id"), nullable=False, index=True)
    file_path = db.Column(db.String(512), nullable=False)
    file_name = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(128), nullable=False, index=True)
    file_size = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), nullable=False)  # clean, malicious, suspicious, unknown, whitelisted
    threat_level = db.Column(db.String(16), default="none")  # none, low, medium, high, critical
    positives = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)
    malicious = db.Column(db.Integer, default=0)
    suspicious = db.Column(db.Integer, default=0)
    undetected = db.Column(db.Integer, default=0)
    action = db.Column(db.String(32), default="none")  # none, quarantined, deleted, ignored
    quarantine_path = db.Column(db.String(512), nullable=True)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    agent = db.relationship("Agent", backref="scans")

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "status": self.status,
            "threat_level": self.threat_level,
            "positives": self.positives,
            "total": self.total,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "undetected": self.undetected,
            "action": self.action,
            "quarantine_path": self.quarantine_path,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }


class QuarantineItem(db.Model):
    __tablename__ = "quarantine_items"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), db.ForeignKey("agents.agent_id"), nullable=False, index=True)
    original_path = db.Column(db.String(512), nullable=False)
    quarantine_path = db.Column(db.String(512), nullable=False)
    file_hash = db.Column(db.String(128), nullable=False, index=True)
    reason = db.Column(db.String(64), default="malicious")
    quarantined_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    restored = db.Column(db.Boolean, default=False)
    restored_at = db.Column(db.DateTime, nullable=True)

    agent = db.relationship("Agent", backref="quarantine_items")

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "file_hash": self.file_hash,
            "reason": self.reason,
            "quarantined_at": self.quarantined_at.isoformat() if self.quarantined_at else None,
            "restored": self.restored,
            "restored_at": self.restored_at.isoformat() if self.restored_at else None,
        }


class Policy(db.Model):
    __tablename__ = "policies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(512), nullable=True)
    auto_quarantine = db.Column(db.Boolean, default=False)
    skip_system_dirs = db.Column(db.Boolean, default=True)
    max_file_size_mb = db.Column(db.Integer, default=32)
    cache_ttl_hours = db.Column(db.Integer, default=24)
    malicious_threshold = db.Column(db.Integer, default=1)
    high_risk_threshold = db.Column(db.Integer, default=5)
    critical_threshold = db.Column(db.Integer, default=10)
    is_active = db.Column(db.Boolean, default=True)
    applies_to = db.Column(db.String(64), default="all")  # all or specific agent_id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "auto_quarantine": self.auto_quarantine,
            "skip_system_dirs": self.skip_system_dirs,
            "max_file_size_mb": self.max_file_size_mb,
            "cache_ttl_hours": self.cache_ttl_hours,
            "malicious_threshold": self.malicious_threshold,
            "high_risk_threshold": self.high_risk_threshold,
            "critical_threshold": self.critical_threshold,
            "is_active": self.is_active,
            "applies_to": self.applies_to,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    target_type = db.Column(db.String(32), nullable=True)
    target_id = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User", backref="audit_logs")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
