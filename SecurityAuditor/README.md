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
- **Dashboard**: A minimal FastAPI web UI to visualize findings.
- **Storage**: SQLite-based scan history and vulnerability tracking.

## Installation

1. Create a virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Review and edit `config.yaml` to specify your authorized `targets` (CIDR blocks or hostnames).

## Usage

### Run the Background Daemon
```bash
python run.py --daemon
```

### Run the Web Dashboard
```bash
python run.py --dashboard
```
Then visit: `http://127.0.0.1:8000`

## Architecture
- `src/main.py`: The daemon orchestration loop.
- `src/scanner.py`: AsyncTCP port sweeping.
- `src/detector.py`: Banner identification.
- `src/plugins/`: Plugins for safely auditing specific services.
- `src/storage.py` & `src/reporter.py`: SQLite persistence and JSON reporting.
- `src/api.py`: FastAPI dashboard.
