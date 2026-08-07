import ipaddress
import socket

import requests

from core.logger import setup_logger


logger = setup_logger("reconforge.ip")


def _extract_dns_ips(dns_result):
    """
    Extract IPv4 and IPv6 addresses from the existing DNS result.

    Task:
    - Read A records
    - Read AAAA records
    - Avoid performing duplicate DNS lookups
    """

    ipv4_addresses = []
    ipv6_addresses = []

    if not dns_result:
        return ipv4_addresses, ipv6_addresses

    data = dns_result.get("data", {})
    records = data.get("records", {})

    for value in records.get("A", []):
        if value not in ipv4_addresses:
            ipv4_addresses.append(value)

    for value in records.get("AAAA", []):
        if value not in ipv6_addresses:
            ipv6_addresses.append(value)

    return ipv4_addresses, ipv6_addresses


def _classify_ip(ip_string):
    """
    Classify an IP address.

    Task:
    - Validate the IP
    - Determine IPv4 or IPv6
    - Determine public/private
    - Detect loopback, multicast, link-local, reserved, etc.
    """

    try:
        ip = ipaddress.ip_address(ip_string)

    except ValueError:
        return {
            "valid": False,
            "version": None,
            "public": False,
            "private": False,
            "loopback": False,
            "link_local": False,
            "multicast": False,
            "reserved": False,
        }

    return {
        "valid": True,
        "version": f"IPv{ip.version}",
        "public": ip.is_global,
        "private": ip.is_private,
        "loopback": ip.is_loopback,
        "link_local": ip.is_link_local,
        "multicast": ip.is_multicast,
        "reserved": ip.is_reserved,
    }


def _reverse_dns(ip_string):
    """
    Attempt reverse DNS lookup.

    Task:
    - Resolve an IP address back to a hostname
    - Return None when no PTR record is available
    """

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(
            ip_string
        )

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }

    except (
        socket.herror,
        socket.gaierror,
        OSError,
    ):
        return None


def _lookup_geolocation(
    ip_string,
    timeout=5.0
):
    """
    Perform optional basic public-IP geolocation.

    Task:
    - Get approximate country/region/city
    - Get ASN/organization when available

    Important:
    This is approximate network-location data,
    not an exact physical location.
    """

    classification = _classify_ip(
        ip_string
    )

    if not classification["valid"]:
        return {
            "status": "failed",
            "data": {},
            "error": "Invalid IP address.",
        }

    if not classification["public"]:
        return {
            "status": "skipped",
            "data": {},
            "error": (
                "Geolocation skipped because "
                "the IP is not public."
            ),
        }

    url = f"https://ipwho.is/{ip_string}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": (
                    "ReconForge/1.0 "
                    "(Authorized Reconnaissance Framework)"
                )
            },
        )

        response.raise_for_status()

        payload = response.json()

        if not payload.get("success", True):
            return {
                "status": "failed",
                "data": {},
                "error": payload.get(
                    "message",
                    "Geolocation service returned an error."
                ),
            }

        connection = payload.get(
            "connection",
            {}
        )

        data = {
            "country": payload.get(
                "country"
            ),
            "country_code": payload.get(
                "country_code"
            ),
            "region": payload.get(
                "region"
            ),
            "city": payload.get(
                "city"
            ),
            "latitude": payload.get(
                "latitude"
            ),
            "longitude": payload.get(
                "longitude"
            ),
            "timezone": (
                payload.get("timezone", {})
                .get("id")
            ),
            "asn": connection.get(
                "asn"
            ),
            "organization": connection.get(
                "org"
            ),
            "isp": connection.get(
                "isp"
            ),
        }

        return {
            "status": "success",
            "data": data,
            "error": None,
        }

    except requests.Timeout:
        return {
            "status": "failed",
            "data": {},
            "error": (
                f"Geolocation request timed out "
                f"after {timeout} seconds."
            ),
        }

    except requests.RequestException as error:
        return {
            "status": "failed",
            "data": {},
            "error": (
                f"Geolocation request failed: {error}"
            ),
        }

    except ValueError as error:
        return {
            "status": "failed",
            "data": {},
            "error": (
                f"Invalid geolocation response: {error}"
            ),
        }


def _analyze_single_ip(
    ip_string,
    geolocation=True,
    timeout=5.0
):
    """
    Analyze one IP address.

    Task:
    - Classify the IP
    - Perform reverse DNS
    - Optionally perform geolocation
    """

    classification = _classify_ip(
        ip_string
    )

    reverse_dns = _reverse_dns(
        ip_string
    )

    geo_result = {
        "status": "skipped",
        "data": {},
        "error": None,
    }

    if geolocation:
        geo_result = _lookup_geolocation(
            ip_string,
            timeout,
        )

    return {
        "ip_address": ip_string,
        "classification": classification,
        "reverse_dns": reverse_dns,
        "geolocation": geo_result,
    }


def lookup_ip_information(
    dns_result,
    geolocation=True,
    timeout=5.0
):
    """
    Main IP reconnaissance controller.

    Collects:
    - IPv4 addresses
    - IPv6 addresses
    - Public/private classification
    - Reverse DNS
    - Optional approximate geolocation
    - ASN/organization when available
    """

    logger.info(
        "Starting IP information reconnaissance"
    )

    ipv4_addresses, ipv6_addresses = (
        _extract_dns_ips(
            dns_result
        )
    )

    all_ips = (
        ipv4_addresses
        + ipv6_addresses
    )

    if not all_ips:
        message = (
            "No IP addresses were available "
            "from DNS reconnaissance."
        )

        logger.warning(message)

        return {
            "module": "ip_lookup",
            "status": "skipped",
            "data": {
                "ipv4_addresses": [],
                "ipv6_addresses": [],
                "results": [],
            },
            "observations": [],
            "errors": [message],
        }

    results = []
    errors = []

    for ip_string in all_ips:

        logger.info(
            "Analyzing IP address %s",
            ip_string
        )

        result = _analyze_single_ip(
            ip_string,
            geolocation=geolocation,
            timeout=timeout,
        )

        results.append(
            result
        )

        geo_error = (
            result["geolocation"]
            .get("error")
        )

        if geo_error:
            errors.append(
                f"{ip_string}: {geo_error}"
            )

    status = (
        "partial"
        if errors
        else "success"
    )

    logger.info(
        "IP reconnaissance completed "
        "with %d IP address(es)",
        len(results)
    )

    return {
        "module": "ip_lookup",
        "status": status,
        "data": {
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "results": results,
        },
        "observations": [],
        "errors": errors,
    }