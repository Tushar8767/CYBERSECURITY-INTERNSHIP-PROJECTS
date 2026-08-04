# 🛡️ Project 04 — Blue Team: Security Monitoring & Incident Response

# Rakshak LogGuard

**Desktop Security Log Analysis & Incident Response Platform**

> Somewhere in the noise, an attacker left a trace. Find it.

---

## 📌 Project Overview

Rakshak LogGuard is a desktop-based security log analysis application developed as part of **Project 04 – Blue Team: Security Monitoring & Incident Response** during my cybersecurity internship.

The application was built to assist in analyzing Linux authentication and system logs by identifying suspicious activities, applying predefined detection rules, classifying security incidents, and generating professional investigation reports.

The project focuses on defensive cybersecurity and Security Operations Center (SOC) investigation methodology using only authorized sample log files provided for educational purposes.

---

# 🎯 Objectives

- Analyze Linux authentication and system logs
- Detect suspicious login activities
- Identify brute-force attacks
- Detect privilege escalation
- Identify persistence mechanisms
- Classify security incidents
- Generate alerts
- Produce professional incident response reports

---

# 🖥️ Application Features

## Evidence Processing

- Upload authentication and system log files
- SHA-256 evidence hashing
- File validation
- Secure evidence handling
- Log type identification

---

## Log Analysis

- Authentication log parsing
- System log parsing
- Event normalization
- Event classification
- Timeline generation
- IOC extraction

---

## Detection

- Rule-based detection engine
- Authentication anomaly detection
- Privilege escalation detection
- Account creation detection
- Persistence detection
- Defense evasion detection

---

## Incident Analysis

- Alert generation
- Incident classification
- Severity assignment
- Risk assessment
- Security recommendations

---

## Reporting

- Investigation summary
- Professional PDF report
- CSV exports
- Timeline report
- IOC report

---

# 📊 Investigation Summary

| Metric | Value |
|----------|-------|
| Total Events | 371 |
| Successfully Parsed | 222 |
| Unsupported Events | 149 |
| Parser Coverage | 59.84% |
| Rule Matched Events | 97 |
| Major Findings | 9 |
| Correlated Incidents | 1 |
| Incident Risk Score | 94/100 |
| Internal Severity | Critical |
| Internship Severity | High |

---

# 🚨 Key Findings

The investigation successfully identified:

- SSH username enumeration
- SSH brute-force attack
- Successful login after brute-force
- Root privilege escalation
- Unauthorized account creation
- Privileged group modification
- Cron-based persistence
- Remote payload execution
- Shell history removal
- Backdoor account reuse

---

# 🧩 Detection Rules

The application currently implements predefined detection logic for:

- AUTH-001 — Repeated SSH Authentication Failures
- AUTH-002 — Username Enumeration
- AUTH-003 — Successful Login After Failures
- PRIV-001 — Root Privilege Escalation
- ACCOUNT-001 — Unauthorized Account Creation
- PRIV-002 — Privileged Group Modification
- PERSIST-001 — Malicious Cron Task Creation
- PERSIST-002 — Remote Payload Execution
- DEFENSE-001 — Shell History Removal
- AUTH-005 — Backdoor Account Login

---

# 🛠 Technologies Used

- Python
- Tkinter
- SQLite
- Pandas
- CSV
- JSON
- Linux Log Analysis

---

# 📂 Project Structure

```text
Project-04-Blue-Team
│
├── application/
│   └── Rakshak LogGuard
│
├── report/
│   └── Incident Response Report.pdf
│
├── screenshots/
│
├── exports/
│
├── sample-logs/
│
└── README.md
```

---

# 🚀 Getting Started

Clone the repository

```bash
git clone https://github.com/Tushar8767/CYBERSECURITY-INTERNSHIP-PROJECTS/tree/9f3969d15f42fed855b5490db62735ffdf01d2ee/Project-04-Blue-Team
```

Navigate to the project

```bash
cd Project-04-Blue-Team
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python main.py
```

> Replace `main.py` with the correct entry point if your project uses another filename.

---

# 📑 Workflow

```
Upload Logs
      ↓
Validate Files
      ↓
Parse Logs
      ↓
Normalize Events
      ↓
Apply Detection Rules
      ↓
Generate Alerts
      ↓
Classify Incident
      ↓
Generate Timeline
      ↓
Export Report
```

---

# 📄 Deliverables

- Desktop Log Analysis Application
- Incident Response Report
- Detection Logic Documentation
- Incident Classification
- CSV Investigation Reports
- Screenshots
- Source Code

---

# 🔒 Ethical Notice

This project was developed strictly for educational purposes using authorized sample log files supplied as part of a cybersecurity internship.

No production systems were targeted, and no unauthorized testing was performed.

---

# 🚀 Future Improvements

The following enhancements are planned for future versions of Rakshak LogGuard:

- Full Log Analysis Dashboard
- Raw Log Viewer
- Detection Validation & Explainability Engine
- Investigation Integrity Dashboard
- Configurable Detection Rule Library
- Explainable Incident Risk Engine
- MITRE ATT&CK Mapping
- IOC Enrichment
- Multi-log Correlation
- Advanced Report Generator

---

# 📚 What I Learned

Through this project I gained practical experience in Security Operations Center (SOC) investigation techniques including authentication log analysis, brute-force detection, privilege escalation analysis, persistence detection, incident classification, timeline reconstruction, IOC extraction, and professional incident response reporting.

Building Rakshak LogGuard also strengthened my understanding of secure evidence handling, SHA-256 integrity verification, rule-based detection, CSV report generation, and defensive cybersecurity workflows.

---

# 👨‍💻 Author

**Tushar Chaugule**

Cybersecurity Intern

Project 04 — Blue Team: Security Monitoring & Incident Response
