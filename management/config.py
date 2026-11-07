"""Sentinel Cyber Security Suite - Management Server Configuration."""
import os
from dotenv import load_dotenv

# Load environment variables from .env file (if present)
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PRODUCT_NAME = "Sentinel Cyber Security Suite"
MANAGEMENT_NAME = "CS Department Management"

SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY", "dev-secret-change-in-production")
DATABASE_URL = os.environ.get("SENTINEL_DB_URL", "sqlite:///" + os.path.join(BASE_DIR, "sentinel_mgmt.db"))

# API settings
API_PREFIX = "/api"
HOST = os.environ.get("SENTINEL_MGMT_HOST", "0.0.0.0")
PORT = int(os.environ.get("SENTINEL_MGMT_PORT", "8000"))
DEBUG = os.environ.get("SENTINEL_MGMT_DEBUG", "false").lower() == "true"

# Role-based access control
ROLES = {
    "cs_admin": "Full access - manage agents, policies, users, quarantine",
    "cs_analyst": "View scans, manage quarantine, analyze threats",
    "cs_viewer": "Read-only access to dashboard and reports",
}

# Default agent token (agents use this to register)
DEFAULT_AGENT_TOKEN = os.environ.get("SENTINEL_DEFAULT_AGENT_TOKEN", "sentinel-agent-token-change-me")
