# Rakshak LogGuard

**Desktop Security Log Analysis and Incident Response Platform**

**Internship Submission:** Project 04 - Blue Team: Security Monitoring and Incident Response

Rakshak LogGuard is an offline Python desktop application for safe evidence ingestion, Linux authentication log parsing, detection-rule execution, incident correlation, IOC extraction, CSV export, and PDF incident reporting.

The internship assignment required log analysis, detection logic, incident classification, response recommendations, and professional reporting. Rakshak LogGuard extends the assignment by automating these activities through a secure desktop application.

## Security Notice

This project is intended for defensive security, educational use, and authorized log analysis only. Uploaded files are processed locally and are never executed.

## Features

- CustomTkinter desktop interface with upload, dashboard, scan, events, alerts, incidents, timeline, IOC, rules, investigations, and reports pages.
- File pre-scan with hashes, extension checks, MIME hints, executable signatures, archive safety checks, entropy, optional YARA, optional ClamAV, and suspicious text indicators.
- Linux `auth.log` parser with year selection and preservation of malformed lines.
- Declarative detection rules for brute force, username enumeration, compromise, privilege escalation, persistence, and defense evasion.
- Deterministic risk scoring and one correlated incident for connected attack chains.
- SQLite persistence through SQLAlchemy.
- CSV exports with formula-injection protection.
- PDF incident response report generated from real investigation data.

## Install

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Bash:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Use **Analyze Sample Log** to validate the full workflow with `samples/sanitized_auth.log`.

## Test And Lint

```bash
pytest
ruff check .
```

## Package

```bash
pyinstaller --onefile --windowed --name RakshakLogGuard app.py
```

## Methodology

Evidence ingestion -> hash generation -> file pre-scan -> safe/blocked decision -> parsing -> normalization -> baseline classification -> detection -> alert creation -> incident correlation -> risk scoring -> recommendations -> CSV/PDF reporting -> closure.

## Supported Formats

Initial log formats: `.log`, `.txt`, `.csv`, `.json`.

Safe archive inspection: `.zip`, `.tar`, `.tar.gz`, `.gz` where supported by Python archive libraries.

## Current Limitations

- Initial parser focuses on Linux authentication/syslog-style evidence.
- YARA and ClamAV are optional and reported as unavailable when not installed.
- Response actions are recommendations only; the app does not block IPs, disable accounts, alter firewalls, or execute uploaded content.

## Future Roadmap

Future Rakshak integration can add Trinetra multi-host monitoring, Kavach approved containment actions, EVTX parsing, web server logs, firewall logs, live local monitoring, encrypted log transport, threat-intelligence lookup, role-based access, and audit trails.
