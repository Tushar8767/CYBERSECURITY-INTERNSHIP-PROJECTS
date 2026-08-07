import ipaddress
import re
from urllib.parse import urlparse


class TargetValidationError(Exception):
    """Raised when the supplied reconnaissance target is invalid."""
    pass


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:"
    r"[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\."
    r")+"
    r"[a-zA-Z]{2,63}$"
)


def _clean_input(target: str) -> str:
    """
    Remove surrounding whitespace and validate basic input.
    """

    if not isinstance(target, str):
        raise TargetValidationError("Target must be a string.")

    target = target.strip()

    if not target:
        raise TargetValidationError("Target cannot be empty.")

    if len(target) > 2048:
        raise TargetValidationError("Target is too long.")

    return target


def _parse_target(target: str):
    """
    Parse either:
        example.com
        www.example.com
        https://example.com/path
        http://example.com/test?id=1
    """

    if "://" not in target:
        target_to_parse = f"https://{target}"
    else:
        target_to_parse = target

    try:
        parsed = urlparse(target_to_parse)
    except ValueError as error:
        raise TargetValidationError(
            f"Unable to parse target: {error}"
        ) from error

    return parsed


def _validate_scheme(parsed):
    """
    Only allow HTTP and HTTPS targets.
    """

    allowed_schemes = {"http", "https"}

    if parsed.scheme.lower() not in allowed_schemes:
        raise TargetValidationError(
            "Only HTTP and HTTPS targets are supported."
        )


def _normalize_hostname(hostname: str) -> str:
    """
    Normalize and validate hostname.
    """

    if not hostname:
        raise TargetValidationError(
            "No hostname could be extracted from the target."
        )

    hostname = hostname.strip().lower()

    # Remove trailing DNS dot:
    # example.com. -> example.com
    hostname = hostname.rstrip(".")

    if not hostname:
        raise TargetValidationError("Hostname is empty.")

    return hostname


def _is_ip_address(hostname: str) -> bool:
    """
    Determine whether hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _validate_domain(hostname: str):
    """
    Validate a normal public-style domain name.
    """

    if not DOMAIN_PATTERN.match(hostname):
        raise TargetValidationError(
            f"'{hostname}' is not a valid domain name."
        )


def _validate_ip(hostname: str):
    """
    Validate an IP target.

    For this internship project we reject private, loopback,
    link-local and reserved IP addresses by default.
    """

    try:
        ip = ipaddress.ip_address(hostname)

    except ValueError as error:
        raise TargetValidationError(
            f"Invalid IP address: {hostname}"
        ) from error

    if ip.is_loopback:
        raise TargetValidationError(
            "Loopback IP addresses are not allowed."
        )

    if ip.is_private:
        raise TargetValidationError(
            "Private IP addresses are not allowed."
        )

    if ip.is_link_local:
        raise TargetValidationError(
            "Link-local IP addresses are not allowed."
        )

    if ip.is_multicast:
        raise TargetValidationError(
            "Multicast IP addresses are not valid targets."
        )

    if ip.is_unspecified:
        raise TargetValidationError(
            "Unspecified IP addresses are not valid targets."
        )


def normalize_target(target: str) -> dict:
    """
    Validate and normalize a reconnaissance target.

    Returns:
        {
            "original": "...",
            "hostname": "...",
            "https_url": "...",
            "http_url": "...",
            "input_scheme": "...",
            "is_ip": False
        }
    """

    original = _clean_input(target)

    parsed = _parse_target(original)

    _validate_scheme(parsed)

    hostname = _normalize_hostname(parsed.hostname)

    is_ip = _is_ip_address(hostname)

    if is_ip:
        _validate_ip(hostname)
    else:
        _validate_domain(hostname)

    return {
        "original": original,
        "hostname": hostname,
        "https_url": f"https://{hostname}",
        "http_url": f"http://{hostname}",
        "input_scheme": parsed.scheme.lower(),
        "is_ip": is_ip,
    }