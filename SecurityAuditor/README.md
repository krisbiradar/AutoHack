# Security Auditor Service

A lightweight, background Python daemon that routinely performs safe, non-destructive defensive security scans on explicitly authorized networks and hosts. It uses `asyncio` for efficient port scanning and features a plugin architecture to audit identified services for common misconfigurations (e.g., exposed databases, password-enabled SSH).

## Disclaimer
**This tool must ONLY be used on networks and systems where you have explicit authorization to perform security testing.** Scanning unauthorized networks is illegal. This tool is built strictly for defensive auditing and does *not* perform brute-force credential attacks or exploits.

## Features
- **Daemon Mode**: Runs continuously, waking up at configured intervals.
- **Async Scanner**: High-speed, non-blocking TCP port scanning.
- **Service Detection**: Banner grabbing and basic protocol handshakes.
- **Plugin System**: Easily extensible to add new checks for specific services.
  - SSH: Checks for password authentication.
  - Redis: Checks for unauthenticated access (PING check).
  - MongoDB: Checks for unauthenticated database listing.
  - HTTP/HTTPS: Analyzes server headers for version disclosures.
  - PostgreSQL: Tests for unauthenticated standard user access on the default DB.
  - MySQL: Tests for unauthenticated root access.
  - Jenkins: Checks for unauthenticated script console access.
- **Advanced Context**: Integrates `nmap -sV` for deep version profiling on discovered services.
- **Alerting**: Supports exporting JSON reports and pushing real-time high-risk notifications by email (via standard SMTP configurable in `src/reporter.py`).
- **Dashboard Server**: A minimal FastAPI web UI that acts as a reporting server to visualize findings.
- **Storage**: SQLite-based scan history and vulnerability tracking written to `data/auditor.db` and log files written to the `logs` folder.

## Installation

1. Create a virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Review and edit `config.yaml` to specify your authorized `targets` (CIDR blocks or hostnames).

## Configuration

Settings are controlled primarily via `config.yaml`.
- Define explicit target IPs or CIDR boundaries in the `targets` block.
- Adjust `daemon.scan_interval_minutes` to govern loop speed.
- Turn `scanner.full_scan` to `true` to scan all 65k ports instead of the default common list.

### Alerting Notification Setup
To receive email notifications for critical vulnerabilities:
1. Open `src/reporter.py`.
2. Locate the `_send_email_alert` function.
3. Uncomment the SMTP connection code and input your respective credentials or local SMTP relay settings.

## Usage

### Run the Background Daemon
Executes the main scanning loop and stores findings in the local SQLite database.
```bash
python run.py --daemon
```

### Run the Web Dashboard Server
The tool includes a built-in FastAPI web server that acts as a real-time dashboard for your scan results.
```bash
python run.py --dashboard
```
Then visit: `http://127.0.0.1:8000`

Using the dashboard, you can monitor the health and specific risk items (Low/Medium/High) of all mapped infrastructure.

## Architecture
- `src/main.py`: The daemon orchestration loop.
- `src/scanner.py`: AsyncTCP port sweeping.
- `src/detector.py`: Banner identification.
- `src/plugins/`: Plugins for safely auditing specific services.
- `src/storage.py` & `src/reporter.py`: SQLite persistence and JSON reporting.
- `src/api.py`: FastAPI dashboard.
