from __future__ import annotations

import mimetypes
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from config.constants import ALLOWED_EXTENSIONS, ARCHIVE_EXTENSIONS, DANGEROUS_EXTENSIONS
from config.settings import settings
from core.entropy_analyzer import shannon_entropy
from core.hash_service import calculate_hashes
from models.schemas import FileScanResult

SUSPICIOUS_TEXT_PATTERNS = [
    r"curl\s+.*\|\s*(bash|sh)", r"wget\s+.*\|\s*(bash|sh)", r"powershell\s+-(enc|encodedcommand)",
    r"Invoke-WebRequest", r"certutil", r"bitsadmin", r"\bnc(at)?\s+-e", r"bash\s+-i",
    r"/dev/tcp/", r"chmod\s+\+x", r"base64\s+-d", r"python\s+-c", r"perl\s+-e",
    r"ruby\s+-e", r"mkfifo", r"history\s+-c", r"\.bash_history", r"crontab", r"/etc/sudoers",
]

SIGNATURES = [
    (b"MZ", "Windows PE"),
    (b"\x7fELF", "Linux ELF"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Fat Mach-O"),
    (b"\xfe\xed\xfa", "Mach-O"),
    (b"PK\x03\x04", "ZIP/JAR archive"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut"),
]


def normalize_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)


def extension_for(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    return path.suffix.lower()


def detect_signature(path: Path) -> str | None:
    data = path.read_bytes()[:16]
    for sig, label in SIGNATURES:
        if data.startswith(sig):
            return label
    first_line = path.read_bytes()[:128]
    if first_line.startswith(b"#!") and any(x in first_line for x in [b"/sh", b"python", b"perl", b"bash"]):
        return "Executable shebang script"
    return None


def has_double_extension(path: Path) -> bool:
    suffixes = [s.lower() for s in path.suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in DANGEROUS_EXTENSIONS


def scan_suspicious_text(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[:2_000_000]
    except OSError:
        return []
    found: list[str] = []
    for pattern in SUSPICIOUS_TEXT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern)
    return found


def _safe_member_name(name: str) -> bool:
    pure = Path(name)
    return not (pure.is_absolute() or ".." in pure.parts)


def inspect_archive(path: Path) -> tuple[list[dict[str, object]], list[str], bool]:
    members: list[dict[str, object]] = []
    reasons: list[str] = []
    blocked = False
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > settings.max_archive_files:
                    return [], ["Archive file-count limit exceeded"], True
                for info in infos:
                    if not _safe_member_name(info.filename):
                        blocked = True
                        reasons.append(f"Archive path traversal detected: {info.filename}")
                    ratio = (info.file_size / max(info.compress_size, 1)) if info.compress_size else 0
                    if ratio > settings.max_compression_ratio:
                        blocked = True
                        reasons.append(f"Excessive compression ratio in {info.filename}")
                    ext = extension_for(Path(info.filename))
                    risk = "High Risk" if ext in DANGEROUS_EXTENSIONS or has_double_extension(Path(info.filename)) else "Safe"
                    if risk == "High Risk":
                        reasons.append(f"Dangerous archive member: {info.filename}")
                    members.append({"filename": info.filename, "size": info.file_size, "extension": ext, "risk": risk})
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                infos = archive.getmembers()
                if len(infos) > settings.max_archive_files:
                    return [], ["Archive file-count limit exceeded"], True
                for info in infos:
                    if info.issym() or info.islnk() or not _safe_member_name(info.name):
                        blocked = True
                        reasons.append(f"Unsafe tar member detected: {info.name}")
                    ext = extension_for(Path(info.name))
                    risk = "High Risk" if ext in DANGEROUS_EXTENSIONS or has_double_extension(Path(info.name)) else "Safe"
                    if risk == "High Risk":
                        reasons.append(f"Dangerous archive member: {info.name}")
                    members.append({"filename": info.name, "size": info.size, "extension": ext, "risk": risk})
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return members, [f"Archive inspection failed: {exc}"], True
    return members, reasons, blocked


def run_yara(path: Path) -> str:
    try:
        import yara  # type: ignore[import-not-found]
    except Exception:
        return "Unavailable"
    rules_dir = settings.rules_dir / "yara"
    try:
        rule_files = list(rules_dir.glob("*.yar"))
        if not rule_files:
            return "No rules"
        compiled = yara.compile(filepaths={p.stem: str(p) for p in rule_files})
        matches = compiled.match(str(path))
        return "Match: " + ", ".join(m.rule for m in matches) if matches else "No match"
    except Exception as exc:
        return f"Error: {exc}"


def run_clamav(path: Path) -> str:
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return "Unavailable"
    try:
        proc = subprocess.run(
            [clamscan, "--no-summary", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Error: {exc}"
    if proc.returncode == 1:
        return "Malware: " + proc.stdout.strip()
    if proc.returncode == 0:
        return "No malware"
    return f"Error: {proc.stderr.strip() or proc.stdout.strip()}"


def scan_file(path: Path, hostname: str = "") -> FileScanResult:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)
    ext = extension_for(path)
    hashes = calculate_hashes(path)
    size = path.stat().st_size
    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    signature = detect_signature(path)
    entropy = shannon_entropy(path)
    archive = ext in ARCHIVE_EXTENSIONS or zipfile.is_zipfile(path) or tarfile.is_tarfile(path)
    archive_members: list[dict[str, object]] = []
    reasons: list[str] = []
    blocked = False

    if size == 0:
        blocked = True
        reasons.append("Empty files cannot be analyzed.")
    if size > settings.max_upload_bytes:
        blocked = True
        reasons.append("File exceeds configured upload limit.")
    if ext not in ALLOWED_EXTENSIONS and ext not in ARCHIVE_EXTENSIONS:
        reasons.append(f"Unsupported or risky extension: {ext}")
    if ext in DANGEROUS_EXTENSIONS:
        blocked = True
        reasons.append("Direct executable/script upload is blocked.")
    if has_double_extension(path):
        reasons.append("Dangerous double extension detected.")
    if signature in {"Windows PE", "Linux ELF", "Mach-O/Fat Mach-O", "Mach-O", "Executable shebang script", "Windows shortcut"}:
        blocked = True
        reasons.append(f"Executable signature detected: {signature}")
    if signature == "ZIP/JAR archive" and ext not in ARCHIVE_EXTENSIONS:
        reasons.append("MIME/signature mismatch: archive content with non-archive extension.")
    if entropy > 7.2 and ext in ALLOWED_EXTENSIONS:
        reasons.append("High entropy for a text-oriented log file.")
    if archive:
        archive_members, archive_reasons, archive_blocked = inspect_archive(path)
        reasons.extend(archive_reasons)
        blocked = blocked or archive_blocked

    suspicious = scan_suspicious_text(path) if not signature or "archive" not in signature.lower() else []
    yara_status = run_yara(path)
    clamav_status = run_clamav(path)
    if yara_status.startswith("Match:"):
        reasons.append(yara_status)
    if clamav_status.startswith("Malware:"):
        blocked = True
        reasons.append(clamav_status)

    if blocked:
        risk, decision = "Blocked", "Blocked"
    elif any("Dangerous" in r or "High entropy" in r or "mismatch" in r for r in reasons):
        risk, decision = "Suspicious", "Allow with warning"
    elif suspicious:
        risk, decision = "Low Risk", "Allow with warning"
        reasons.append("Suspicious command text appears to be log evidence; analysis is allowed with warning.")
    else:
        risk, decision = "Safe", "Allow analysis"
        reasons.append("No blocking file-level condition detected.")

    with tempfile.TemporaryDirectory():
        pass

    return FileScanResult(
        original_filename=path.name,
        normalized_filename=normalize_filename(path.name),
        path=path,
        extension=ext,
        size_bytes=size,
        mime_type=mime_type,
        detected_type=signature or ("Archive" if archive else "Text/Unknown"),
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        entropy=round(entropy, 3),
        double_extension=has_double_extension(path),
        executable_signature=signature,
        archive=archive,
        archive_member_count=len(archive_members),
        archive_members=archive_members,
        yara_status=yara_status,
        clamav_status=clamav_status,
        suspicious_text_indicators=suspicious,
        risk=risk,
        decision=decision,
        reasons=reasons,
    )
