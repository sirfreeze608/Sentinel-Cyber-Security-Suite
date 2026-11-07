"""Sentinel Cyber Security Suite - Shared protocol definitions.
Defines the message format used between Sentinel Agents and the CS Department
Management Server. Both sides must agree on these field names.
"""

# Agent registration payload
AGENT_REGISTER_FIELDS = {
    "agent_id": "str - unique agent identifier",
    "hostname": "str - endpoint hostname",
    "os_platform": "str - OS name (e.g., Windows)",
    "agent_version": "str - agent version",
    "token": "str - shared agent token for auth",
}

# Scan result payload (agent -> management)
SCAN_RESULT_FIELDS = {
    "agent_id": "str",
    "file_path": "str",
    "file_name": "str",
    "file_hash": "str - SHA-256",
    "file_size": "int - bytes",
    "status": "str - clean/malicious/suspicious/unknown/whitelisted/skipped",
    "threat_level": "str - none/low/medium/high/critical",
    "positives": "int - engines flagging",
    "total": "int - total engines",
    "malicious": "int",
    "suspicious": "int",
    "undetected": "int",
    "action": "str - none/quarantined/deleted/ignored",
    "quarantine_path": "str | None",
    "scanned_at": "str - ISO8601 timestamp",
}

# Heartbeat payload
HEARTBEAT_FIELDS = {
    "agent_id": "str",
}

# Management -> Agent responses
AGENT_CONFIG_FIELDS = {
    "auto_quarantine": "bool",
    "skip_system_dirs": "bool",
    "max_file_size_mb": "int",
    "cache_ttl_hours": "int",
    "malicious_threshold": "int",
    "high_risk_threshold": "int",
    "critical_threshold": "int",
}

# HTTP status conventions
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409

# Default agent registration token (change in production)
DEFAULT_AGENT_TOKEN = "sentinel-agent-token-change-me"
