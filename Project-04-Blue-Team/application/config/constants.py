from __future__ import annotations

APP_NAME = "Rakshak LogGuard"
APP_SUBTITLE = "Desktop Security Log Analysis and Incident Response Platform"
INTERNSHIP_TITLE = "Project 04 - Blue Team: Security Monitoring and Incident Response"

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".tar.gz"}
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".jar", ".msi", ".iso", ".elf", ".bin", ".app", ".sh",
}

SEVERITY_ORDER = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}
