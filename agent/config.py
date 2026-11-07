"""Sentinel Cyber Security Suite - Agent Configuration."""
import os
from dotenv import load_dotenv

# Load environment variables from .env file (if present)
load_dotenv()

# --- Product branding ---
PRODUCT_NAME = "Sentinel Cyber Security Suite"
AGENT_NAME = "Sentinel Agent"

# --- VirusTotal API ---
VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Management server (CS Department dashboard) ---
MANAGEMENT_URL = os.environ.get("SENTINEL_MGMT_URL", "http://127.0.0.1:8000")
AGENT_TOKEN = os.environ.get("SENTINEL_AGENT_TOKEN", "")
AGENT_ID = os.environ.get("SENTINEL_AGENT_ID", "")

# --- Rate limiting (VirusTotal free tier: 4 requests/minute) ---
VT_REQUESTS_PER_MINUTE = 4
VT_RATE_LIMIT_INTERVAL = 60.0 / VT_REQUESTS_PER_MINUTE

# --- Intelligent scan settings ---
MAX_FILE_SIZE_MB = 32
HASH_CACHE_TTL_HOURS = 24
MALICIOUS_THRESHOLD = 1
HIGH_RISK_THRESHOLD = 5
CRITICAL_THRESHOLD = 10

# --- High-risk file extensions ---
HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".msi", ".scr", ".pif", ".hta", ".cpl", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".zip", ".rar", ".7z", ".iso",
    ".wsf", ".wsh", ".lnk", ".chm",
}

# --- Directories to skip during full scans ---
SKIP_DIRECTORIES = {
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\ProgramData", "$Recycle.Bin", "System Volume Information",
}

# --- Paths ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "sentinel.db")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
LOG_PATH = os.path.join(APP_DIR, "sentinel.log")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
