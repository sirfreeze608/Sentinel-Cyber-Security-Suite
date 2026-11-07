"""Sentinel Cyber Security Suite - CS Department Management Server."""
import os
import platform
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
from config import DATABASE_URL, SECRET_KEY, HOST, PORT, DEBUG, ROLES, DEFAULT_AGENT_TOKEN
from models import db, User, Agent, ScanResult, QuarantineItem, Policy, AuditLog
from auth import (
    generate_token, decode_token, auth_required, role_required, log_audit,
)


def create_app():
    app = Flask(__name__, static_folder=None)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = SECRET_KEY
    CORS(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    # =====================================================================
    # AUTH ENDPOINTS
    # =====================================================================
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return jsonify({"error": "Invalid credentials"}), 401
        if not user.is_active:
            return jsonify({"error": "Account disabled"}), 401
        user.last_login = datetime.utcnow()
        db.session.commit()
        token = generate_token(user)
        log_audit("login", "user", str(user.id), ip_address=request.remote_addr)
        return jsonify({"token": token, "user": user.to_dict()})

    @app.route("/api/auth/me", methods=["GET"])
    @auth_required
    def me():
        return jsonify({"user": g.current_user.to_dict()})

    @app.route("/api/auth/roles", methods=["GET"])
    @auth_required
    @role_required("cs_admin")
    def roles():
        return jsonify({"roles": ROLES})

    # =====================================================================
    # USER MANAGEMENT (cs_admin only)
    # =====================================================================
    @app.route("/api/users", methods=["GET"])
    @auth_required
    @role_required("cs_admin")
    def list_users():
        users = User.query.all()
        return jsonify({"users": [u.to_dict() for u in users]})

    @app.route("/api/users", methods=["POST"])
    @auth_required
    @role_required("cs_admin")
    def create_user():
        data = request.get_json() or {}
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role", "cs_viewer")
        if not username or not email or not password:
            return jsonify({"error": "Username, email, and password required"}), 400
        if role not in ROLES:
            return jsonify({"error": "Invalid role"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 409
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_audit("create_user", "user", str(user.id),
                  details="Created user " + username + " with role " + role,
                  ip_address=request.remote_addr)
        return jsonify({"user": user.to_dict()}), 201

    @app.route("/api/users/<int:user_id>", methods=["PUT"])
    @auth_required
    @role_required("cs_admin")
    def update_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        data = request.get_json() or {}
        if "role" in data and data["role"] in ROLES:
            user.role = data["role"]
        if "is_active" in data:
            user.is_active = bool(data["is_active"])
        if "password" in data and data["password"]:
            user.set_password(data["password"])
        db.session.commit()
        log_audit("update_user", "user", str(user_id),
                  details="Updated user " + user.username,
                  ip_address=request.remote_addr)
        return jsonify({"user": user.to_dict()})

    @app.route("/api/users/<int:user_id>", methods=["DELETE"])
    @auth_required
    @role_required("cs_admin")
    def delete_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user.id == g.current_user.id:
            return jsonify({"error": "Cannot delete yourself"}), 400
        db.session.delete(user)
        db.session.commit()
        log_audit("delete_user", "user", str(user_id),
                  details="Deleted user " + user.username,
                  ip_address=request.remote_addr)
        return jsonify({"message": "User deleted"})

    # =====================================================================
    # AGENT MANAGEMENT
    # =====================================================================
    @app.route("/api/agents", methods=["GET"])
    @auth_required
    def list_agents():
        agents = Agent.query.all()
        return jsonify({"agents": [a.to_dict() for a in agents]})

    @app.route("/api/agents/<agent_id>", methods=["GET"])
    @auth_required
    def get_agent(agent_id):
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
        return jsonify({"agent": agent.to_dict()})

    @app.route("/api/agents/register", methods=["POST"])
    def register_agent():
        """Agent self-registration endpoint."""
        data = request.get_json() or {}
        token = data.get("token", "")
        agent_id = data.get("agent_id", "")
        hostname = data.get("hostname", platform.node())
        os_platform = data.get("os_platform", platform.system())
        agent_version = data.get("agent_version", "1.0.0")
        if token != DEFAULT_AGENT_TOKEN:
            return jsonify({"error": "Invalid agent token"}), 403
        if not agent_id:
            return jsonify({"error": "agent_id required"}), 400
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if agent:
            agent.hostname = hostname
            agent.os_platform = os_platform
            agent.agent_version = agent_version
            agent.is_online = True
            agent.last_seen = datetime.utcnow()
        else:
            agent = Agent(
                agent_id=agent_id,
                hostname=hostname,
                os_platform=os_platform,
                agent_version=agent_version,
                api_key=os.urandom(24).hex(),
                is_online=True,
                last_seen=datetime.utcnow(),
            )
            db.session.add(agent)
        db.session.commit()
        return jsonify({"agent": agent.to_dict(), "api_key": agent.api_key})

    @app.route("/api/agents/<agent_id>/heartbeat", methods=["POST"])
    def agent_heartbeat(agent_id):
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
        agent.is_online = True
        agent.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "ok"})

    # =====================================================================
    # SCAN RESULTS
    # =====================================================================
    @app.route("/api/scan_result", methods=["POST"])
    def ingest_scan_result():
        """Agent pushes scan results to management."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing authorization"}), 401
        token = auth_header.split(" ", 1)[1]
        if token != DEFAULT_AGENT_TOKEN:
            return jsonify({"error": "Invalid agent token"}), 403
        data = request.get_json() or {}
        agent_id = data.get("agent_id")
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            agent = Agent(
                agent_id=agent_id,
                hostname=data.get("hostname", "unknown"),
                os_platform="Windows",
                api_key=os.urandom(24).hex(),
                is_online=True,
                last_seen=datetime.utcnow(),
            )
            db.session.add(agent)
            db.session.flush()
        result = ScanResult(
            agent_id=agent_id,
            file_path=data.get("file_path", ""),
            file_name=data.get("file_name", ""),
            file_hash=data.get("file_hash", ""),
            file_size=data.get("file_size", 0),
            status=data.get("status", "unknown"),
            threat_level=data.get("threat_level", "none"),
            positives=data.get("positives", 0),
            total=data.get("total", 0),
            malicious=data.get("malicious", 0),
            suspicious=data.get("suspicious", 0),
            undetected=data.get("undetected", 0),
            action=data.get("action", "none"),
            quarantine_path=data.get("quarantine_path"),
            scanned_at=datetime.fromisoformat(data.get("scanned_at"))
            if data.get("scanned_at") else datetime.utcnow(),
        )
        db.session.add(result)
        # update agent stats
        agent.total_scans = (agent.total_scans or 0) + 1
        if result.status == "malicious":
            agent.total_threats = (agent.total_threats or 0) + 1
        if result.action == "quarantined":
            agent.total_quarantined = (agent.total_quarantined or 0) + 1
        agent.last_seen = datetime.utcnow()
        agent.is_online = True
        db.session.commit()
        return jsonify({"status": "ingested", "id": result.id})

    @app.route("/api/scans", methods=["GET"])
    @auth_required
    def list_scans():
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        status_filter = request.args.get("status")
        threat_filter = request.args.get("threat_level")
        agent_filter = request.args.get("agent_id")
        query = ScanResult.query
        if status_filter:
            query = query.filter_by(status=status_filter)
        if threat_filter:
            query = query.filter_by(threat_level=threat_filter)
        if agent_filter:
            query = query.filter_by(agent_id=agent_filter)
        pagination = query.order_by(ScanResult.scanned_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False)
        return jsonify({
            "scans": [s.to_dict() for s in pagination.items],
            "total": pagination.total,
            "page": page,
            "per_page": per_page,
            "pages": pagination.pages,
        })

    @app.route("/api/scans/<int:scan_id>", methods=["GET"])
    @auth_required
    def get_scan(scan_id):
        scan = db.session.get(ScanResult, scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({"scan": scan.to_dict()})

    # =====================================================================
    # QUARANTINE MANAGEMENT
    # =====================================================================
    @app.route("/api/quarantine", methods=["GET"])
    @auth_required
    def list_quarantine():
        agent_filter = request.args.get("agent_id")
        query = QuarantineItem.query.filter_by(restored=False)
        if agent_filter:
            query = query.filter_by(agent_id=agent_filter)
        items = query.order_by(QuarantineItem.quarantined_at.desc()).all()
        return jsonify({"quarantine": [q.to_dict() for q in items]})

    @app.route("/api/quarantine/<int:q_id>/restore", methods=["POST"])
    @auth_required
    @role_required("cs_admin", "cs_analyst")
    def restore_quarantine(q_id):
        item = db.session.get(QuarantineItem, q_id)
        if not item:
            return jsonify({"error": "Quarantine item not found"}), 404
        data = request.get_json() or {}
        destination = data.get("destination", "")
        if not destination:
            return jsonify({"error": "destination required"}), 400
        item.restored = True
        item.restored_at = datetime.utcnow()
        db.session.commit()
        log_audit("restore_quarantine", "quarantine", str(q_id),
                  details="Restored to " + destination,
                  ip_address=request.remote_addr)
        return jsonify({"message": "Restored", "item": item.to_dict()})

    @app.route("/api/quarantine/<int:q_id>/delete", methods=["POST"])
    @auth_required
    @role_required("cs_admin", "cs_analyst")
    def delete_quarantine(q_id):
        item = db.session.get(QuarantineItem, q_id)
        if not item:
            return jsonify({"error": "Quarantine item not found"}), 404
        item.restored = True  # mark as handled
        db.session.commit()
        log_audit("delete_quarantine", "quarantine", str(q_id),
                  details="Permanently deleted",
                  ip_address=request.remote_addr)
        return jsonify({"message": "Deleted"})

    # =====================================================================
    # POLICY MANAGEMENT
    # =====================================================================
    @app.route("/api/policies", methods=["GET"])
    @auth_required
    def list_policies():
        policies = Policy.query.all()
        return jsonify({"policies": [p.to_dict() for p in policies]})

    @app.route("/api/policies", methods=["POST"])
    @auth_required
    @role_required("cs_admin")
    def create_policy():
        data = request.get_json() or {}
        policy = Policy(
            name=data.get("name", "Untitled Policy"),
            description=data.get("description"),
            auto_quarantine=data.get("auto_quarantine", False),
            skip_system_dirs=data.get("skip_system_dirs", True),
            max_file_size_mb=data.get("max_file_size_mb", 32),
            cache_ttl_hours=data.get("cache_ttl_hours", 24),
            malicious_threshold=data.get("malicious_threshold", 1),
            high_risk_threshold=data.get("high_risk_threshold", 5),
            critical_threshold=data.get("critical_threshold", 10),
            is_active=data.get("is_active", True),
            applies_to=data.get("applies_to", "all"),
        )
        db.session.add(policy)
        db.session.commit()
        log_audit("create_policy", "policy", str(policy.id),
                  details="Created policy " + policy.name,
                  ip_address=request.remote_addr)
        return jsonify({"policy": policy.to_dict()}), 201

    @app.route("/api/policies/<int:policy_id>", methods=["PUT"])
    @auth_required
    @role_required("cs_admin")
    def update_policy(policy_id):
        policy = db.session.get(Policy, policy_id)
        if not policy:
            return jsonify({"error": "Policy not found"}), 404
        data = request.get_json() or {}
        for field in ["name", "description", "auto_quarantine", "skip_system_dirs",
                      "max_file_size_mb", "cache_ttl_hours", "malicious_threshold",
                      "high_risk_threshold", "critical_threshold", "is_active", "applies_to"]:
            if field in data:
                setattr(policy, field, data[field])
        db.session.commit()
        log_audit("update_policy", "policy", str(policy_id),
                  details="Updated policy " + policy.name,
                  ip_address=request.remote_addr)
        return jsonify({"policy": policy.to_dict()})

    @app.route("/api/policies/<int:policy_id>", methods=["DELETE"])
    @auth_required
    @role_required("cs_admin")
    def delete_policy(policy_id):
        policy = db.session.get(Policy, policy_id)
        if not policy:
            return jsonify({"error": "Policy not found"}), 404
        db.session.delete(policy)
        db.session.commit()
        log_audit("delete_policy", "policy", str(policy_id),
                  details="Deleted policy " + policy.name,
                  ip_address=request.remote_addr)
        return jsonify({"message": "Policy deleted"})

    # =====================================================================
    # DASHBOARD STATS
    # =====================================================================
    @app.route("/api/dashboard/stats", methods=["GET"])
    @auth_required
    def dashboard_stats():
        total_agents = Agent.query.count()
        online_agents = Agent.query.filter_by(is_online=True).count()
        total_scans = ScanResult.query.count()
        total_threats = ScanResult.query.filter_by(status="malicious").count()
        total_quarantined = QuarantineItem.query.filter_by(restored=False).count()
        by_status = db.session.query(
            ScanResult.status, db.func.count(ScanResult.id)
        ).group_by(ScanResult.status).all()
        by_threat = db.session.query(
            ScanResult.threat_level, db.func.count(ScanResult.id)
        ).group_by(ScanResult.threat_level).all()
        recent = ScanResult.query.order_by(ScanResult.scanned_at.desc()).limit(10).all()
        return jsonify({
            "total_agents": total_agents,
            "online_agents": online_agents,
            "total_scans": total_scans,
            "total_threats": total_threats,
            "total_quarantined": total_quarantined,
            "by_status": {s: c for s, c in by_status},
            "by_threat_level": {t: c for t, c in by_threat},
            "recent_scans": [s.to_dict() for s in recent],
        })

    # =====================================================================
    # AUDIT LOGS
    # =====================================================================
    @app.route("/api/audit", methods=["GET"])
    @auth_required
    @role_required("cs_admin", "cs_analyst")
    def list_audit():
        limit = int(request.args.get("limit", 100))
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
        return jsonify({"audit": [a.to_dict() for a in logs]})

    # =====================================================================
    # INITIALIZATION
    # =====================================================================
    def _seed_defaults():
        """Create default admin user and policy if none exist."""
        if not User.query.first():
            admin = User(username="cs_admin", email="admin@sentinel.local", role="cs_admin")
            admin.set_password("SentinelAdmin2026!")
            db.session.add(admin)
            analyst = User(username="cs_analyst", email="analyst@sentinel.local", role="cs_analyst")
            analyst.set_password("SentinelAnalyst2026!")
            db.session.add(analyst)
            viewer = User(username="cs_viewer", email="viewer@sentinel.local", role="cs_viewer")
            viewer.set_password("SentinelViewer2026!")
            db.session.add(viewer)
            db.session.commit()
        if not Policy.query.first():
            policy = Policy(
                name="Default Corporate Policy",
                description="Standard Sentinel policy for CS Department endpoints",
                auto_quarantine=False,
                skip_system_dirs=True,
                max_file_size_mb=32,
                cache_ttl_hours=24,
                malicious_threshold=1,
                high_risk_threshold=5,
                critical_threshold=10,
                is_active=True,
                applies_to="all",
            )
            db.session.add(policy)
            db.session.commit()

    return app


def _seed_defaults():
    """Create default admin user and policy if none exist."""
    with app.app_context():
        if not User.query.first():
            admin = User(username="cs_admin", email="admin@sentinel.local", role="cs_admin")
            admin.set_password("SentinelAdmin2026!")
            db.session.add(admin)
            analyst = User(username="cs_analyst", email="analyst@sentinel.local", role="cs_analyst")
            analyst.set_password("SentinelAnalyst2026!")
            db.session.add(analyst)
            viewer = User(username="cs_viewer", email="viewer@sentinel.local", role="cs_viewer")
            viewer.set_password("SentinelViewer2026!")
            db.session.add(viewer)
            db.session.commit()
        if not Policy.query.first():
            policy = Policy(
                name="Default Corporate Policy",
                description="Standard Sentinel policy for CS Department endpoints",
                auto_quarantine=False,
                skip_system_dirs=True,
                max_file_size_mb=32,
                cache_ttl_hours=24,
                malicious_threshold=1,
                high_risk_threshold=5,
                critical_threshold=10,
                is_active=True,
                applies_to="all",
            )
            db.session.add(policy)
            db.session.commit()


app = create_app()
_seed_defaults()

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
