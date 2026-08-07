import socket
import ssl
from datetime import datetime, timezone

from core.logger import setup_logger


logger = setup_logger("reconforge.tls")


def _create_ssl_context():
    """
    Create a secure SSL/TLS context.

    Task:
    - Uses the system's trusted CA certificates
    - Verifies the remote certificate
    - Verifies that the certificate matches the hostname
    """

    context = ssl.create_default_context()

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    return context


def _extract_name(name_data):
    """
    Convert certificate subject or issuer data
    into a simple dictionary.

    Example input:
        ((('commonName', 'example.com'),),)

    Example output:
        {
            "commonName": "example.com"
        }
    """

    result = {}

    if not name_data:
        return result

    for group in name_data:
        for key, value in group:
            result[key] = value

    return result


def _extract_sans(certificate):
    """
    Extract Subject Alternative Names (SANs).

    SANs contain additional hostnames covered by
    the TLS certificate.
    """

    sans = []

    for san_type, value in certificate.get(
        "subjectAltName",
        []
    ):
        if san_type == "DNS":
            sans.append(value)

    return sans


def _parse_certificate_date(date_string):
    """
    Convert certificate date text into a timezone-aware
    Python datetime object.
    """

    if not date_string:
        return None

    try:
        timestamp = ssl.cert_time_to_seconds(
            date_string
        )

        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc
        )

    except (ValueError, OverflowError):
        return None


def _classify_expiry(expiry_date):
    """
    Determine certificate expiry state.

    Classification:
        Expired         -> certificate already expired
        Critical        -> expires within 7 days
        Expiring Soon   -> expires within 30 days
        Valid           -> more than 30 days remaining
        Unknown         -> expiry could not be calculated
    """

    if expiry_date is None:
        return {
            "status": "Unknown",
            "days_remaining": None,
            "severity": "Informational",
        }

    now = datetime.now(
        timezone.utc
    )

    delta = expiry_date - now

    days_remaining = delta.days

    if days_remaining < 0:
        return {
            "status": "Expired",
            "days_remaining": days_remaining,
            "severity": "High",
        }

    if days_remaining <= 7:
        return {
            "status": "Critical",
            "days_remaining": days_remaining,
            "severity": "High",
        }

    if days_remaining <= 30:
        return {
            "status": "Expiring Soon",
            "days_remaining": days_remaining,
            "severity": "Medium",
        }

    return {
        "status": "Valid",
        "days_remaining": days_remaining,
        "severity": "Informational",
    }


def _open_tls_connection(
    hostname,
    port=443,
    timeout=10.0
):
    """
    Open a verified TLS connection to the target.

    Returns:
        certificate
        TLS version
        cipher information
    """

    context = _create_ssl_context()

    with socket.create_connection(
        (hostname, port),
        timeout=timeout,
    ) as raw_socket:

        with context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        ) as tls_socket:

            certificate = (
                tls_socket.getpeercert()
            )

            tls_version = (
                tls_socket.version()
            )

            cipher = (
                tls_socket.cipher()
            )

            return (
                certificate,
                tls_version,
                cipher,
            )


def inspect_tls_certificate(
    hostname,
    port=443,
    timeout=10.0
):
    """
    Main TLS reconnaissance function.

    Collects:
    - TLS version
    - certificate subject
    - common name
    - issuer
    - SANs
    - serial number
    - validity dates
    - days until expiry
    - expiry classification
    - negotiated cipher
    """

    logger.info(
        "Starting TLS certificate analysis for %s",
        hostname,
    )

    try:

        certificate, tls_version, cipher = (
            _open_tls_connection(
                hostname,
                port,
                timeout,
            )
        )

        subject = _extract_name(
            certificate.get("subject")
        )

        issuer = _extract_name(
            certificate.get("issuer")
        )

        sans = _extract_sans(
            certificate
        )

        valid_from = _parse_certificate_date(
            certificate.get("notBefore")
        )

        valid_until = _parse_certificate_date(
            certificate.get("notAfter")
        )

        expiry = _classify_expiry(
            valid_until
        )

        cipher_name = None
        cipher_protocol = None
        cipher_bits = None

        if cipher:
            cipher_name = cipher[0]
            cipher_protocol = cipher[1]
            cipher_bits = cipher[2]

        data = {
            "hostname": hostname,
            "port": port,
            "tls_version": tls_version,

            "subject": subject,

            "common_name": subject.get(
                "commonName"
            ),

            "issuer": issuer,

            "subject_alt_names": sans,

            "serial_number": certificate.get(
                "serialNumber"
            ),

            "valid_from": (
                valid_from.isoformat()
                if valid_from
                else None
            ),

            "valid_until": (
                valid_until.isoformat()
                if valid_until
                else None
            ),

            "days_remaining": expiry[
                "days_remaining"
            ],

            "certificate_status": expiry[
                "status"
            ],

            "certificate_severity": expiry[
                "severity"
            ],

            "cipher": {
                "name": cipher_name,
                "protocol": cipher_protocol,
                "bits": cipher_bits,
            },
        }

        observations = []

        if expiry["status"] == "Expired":

            observations.append(
                {
                    "title": (
                        "TLS certificate has expired"
                    ),
                    "severity": "High",
                    "evidence": (
                        f"Certificate expired "
                        f"{abs(expiry['days_remaining'])} "
                        f"day(s) ago."
                    ),
                    "recommendation": (
                        "Renew and deploy a valid TLS "
                        "certificate immediately."
                    ),
                }
            )

        elif expiry["status"] == "Critical":

            observations.append(
                {
                    "title": (
                        "TLS certificate expires soon"
                    ),
                    "severity": "High",
                    "evidence": (
                        f"Certificate expires in "
                        f"{expiry['days_remaining']} "
                        f"day(s)."
                    ),
                    "recommendation": (
                        "Renew the certificate before "
                        "expiration."
                    ),
                }
            )

        elif expiry["status"] == "Expiring Soon":

            observations.append(
                {
                    "title": (
                        "TLS certificate approaching expiry"
                    ),
                    "severity": "Medium",
                    "evidence": (
                        f"Certificate expires in "
                        f"{expiry['days_remaining']} "
                        f"day(s)."
                    ),
                    "recommendation": (
                        "Schedule certificate renewal "
                        "before expiration."
                    ),
                }
            )

        logger.info(
            "TLS certificate analysis completed for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "success",
            "data": data,
            "observations": observations,
            "errors": [],
        }

    except ssl.SSLCertVerificationError as error:

        message = (
            f"Certificate verification failed: {error}"
        )

        logger.warning(
            "TLS certificate verification failed for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except ssl.SSLError as error:

        message = (
            f"TLS handshake failed: {error}"
        )

        logger.warning(
            "TLS handshake failed for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except socket.timeout:

        message = (
            f"TLS connection timed out after "
            f"{timeout} seconds."
        )

        logger.warning(
            "TLS timeout for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except socket.gaierror as error:

        message = (
            f"Unable to resolve hostname: {error}"
        )

        logger.warning(
            "TLS hostname resolution failed for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except ConnectionRefusedError:

        message = (
            f"Connection to {hostname}:{port} "
            f"was refused."
        )

        logger.warning(message)

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except OSError as error:

        message = (
            f"TLS network error: {error}"
        )

        logger.warning(
            "TLS network error for %s: %s",
            hostname,
            error,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except Exception as error:

        logger.exception(
            "Unexpected TLS analysis error for %s",
            hostname,
        )

        return {
            "module": "tls_certificate",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [
                f"Unexpected TLS error: {error}"
            ],
        }