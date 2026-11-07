#!/usr/bin/env bash
# deploy_management.sh - Deploys the Sentinel CS Department Management Server
set -euo pipefail

MGMT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/management"
VENV_DIR="$MGMT_DIR/.venv"

echo "=== Sentinel Cyber Security Suite - Management Server Deployer ==="

# 1. Create Python virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# 2. Install dependencies
echo "Installing management dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip install -r "$MGMT_DIR/requirements.txt"

# 3. Generate a secret key if not set
if [ -z "${SENTINEL_SECRET_KEY:-}" ]; then
    export SENTINEL_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    echo "Generated SECRET_KEY. Set SENTINEL_SECRET_KEY env var for production."
fi

# 4. Initialize database and seed defaults
echo "Initializing management database..."
"$VENV_DIR/bin/python" -c "
import os
os.environ.setdefault('SENTINEL_SECRET_KEY', '$SENTINEL_SECRET_KEY')
from app import create_app
app = create_app()
print('Database initialized with default users and policy.')
"

# 5. Start the server
echo "Starting Sentinel Management Server on http://0.0.0.0:8000 ..."
echo "Default credentials:"
echo "  cs_admin / SentinelAdmin2026!"
echo "  cs_analyst / SentinelAnalyst2026!"
echo "  cs_viewer / SentinelViewer2026!"
exec "$VENV_DIR/bin/python" "$MGMT_DIR/app.py"
