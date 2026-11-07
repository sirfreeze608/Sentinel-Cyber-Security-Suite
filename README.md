# Sentinel Cyber Security Suite

Production-ready cybersecurity suite for the CS Department, comprising:

1. **Sentinel Agent** (Python desktop) - VirusTotal-powered intelligent antivirus with real-time monitoring and system tray.
2. **Sentinel Management** (Flask API) - CS Department management server with RBAC, agent registry, scan results, quarantine vault, policies, and audit logging.
3. **Sentinel Dashboard** (React + TypeScript) - Cyber-themed management interface for threat monitoring, network activity, phishing analysis, OSINT, and CS administration.

## Architecture

```
Sentinel Cyber Security Suite/
├── agent/               # Windows desktop antivirus agent (PyInstaller buildable)
├── management/          # Flask CS Department management server
├── dashboard/           # React + TypeScript management dashboard
├── shared/              # Shared protocol definitions
└── deploy/              # Deployment scripts (PowerShell + Bash)
```

## Quick Start

### 1. Management Server (CS Department)
```bash
cd management
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py   # Windows
# or: source .venv/bin/activate && python app.py   # Linux
```
Server runs on http://0.0.0.0:8000

### 2. Dashboard (CS Department)
```bash
cd dashboard
cp .env.example .env.local
npm install
npm run dev
```
Dashboard runs on http://localhost:3000

### 3. Agent (Endpoint)
```powershell
cd agent
pip install -r requirements.txt
python main.py
```
Or build a standalone executable:
```powershell
pip install pyinstaller
pyinstaller sentinel.spec --onefile --noconsole
```

### Default Credentials (Management)
| Role | Username | Password |
|------|----------|----------|
| CS Admin | cs_admin | SentinelAdmin2026! |
| CS Analyst | cs_analyst | SentinelAnalyst2026! |
| CS Viewer | cs_viewer | SentinelViewer2026! |

## VirusTotal API Key

Get a free key at https://www.virustotal.com/gui/join and set it:
- Agent: `config.py` `VT_API_KEY` or `VT_API_KEY` env var
- Free tier: 4 requests/min, 500/day, 32 MB max upload

## Features

- Intelligent hash-first scanning (respects VT rate limits via local cache)
- Real-time folder monitoring (watchdog)
- System tray with quick actions
- Auto-quarantine threats
- CS Department multi-agent management
- Role-based access control (Admin / Analyst / Viewer)
- Quarantine vault with restore/delete
- Scan policy management
- Audit logging
- Threat monitor, network pulse, phishing shield, OSINT addons

## Disclaimer

This suite aggregates VirusTotal engine results and is not a replacement for commercial endpoint protection. Use at your own risk.
