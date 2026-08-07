import socket
import requests

from core.logger import setup_logger


logger = setup_logger(
    "reconforge.preflight"
)


def _check_dns(hostname):
    """
    Check whether the target resolves through DNS.

    Task:
    - Resolve IPv4/IPv6 addresses
    - Remove duplicates
    - Determine whether DNS is operational
    """

    try:
        records = socket.getaddrinfo(
            hostname,
            None,
        )

        addresses = []

        for record in records:
            address = record[4][0]

            if address not in addresses:
                addresses.append(address)

        return {
            "success": bool(addresses),
            "addresses": addresses,
            "error": None,
        }

    except socket.gaierror as error:
        return {
            "success": False,
            "addresses": [],
            "error": str(error),
        }


def _check_web(url, timeout=5):
    """
    Check whether an HTTP/HTTPS endpoint responds.

    Task:
    - Try HEAD first to avoid downloading the page
    - Fall back to GET when HEAD is rejected
    - Record HTTP status
    """

    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "ReconForge/1.0"
            },
        )

        # Some servers reject HEAD even though GET works.
        if response.status_code in {
            400,
            403,
            405,
            501,
        }:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
                headers={
                    "User-Agent":
                        "ReconForge/1.0"
                },
            )

        return {
            "responding": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "error": None,
        }

    except requests.Timeout:
        return {
            "responding": False,
            "status_code": None,
            "final_url": None,
            "error": "Request timed out.",
        }

    except requests.ConnectionError as error:
        return {
            "responding": False,
            "status_code": None,
            "final_url": None,
            "error": str(error),
        }

    except requests.RequestException as error:
        return {
            "responding": False,
            "status_code": None,
            "final_url": None,
            "error": str(error),
        }


def check_target_availability(
    target,
    timeout=5,
):
    """
    Perform ReconForge pre-flight validation.

    This runs BEFORE reconnaissance.

    Task:
    1. Check DNS resolution
    2. Test HTTPS
    3. Fall back to HTTP
    4. Classify target availability
    """

    hostname = target["hostname"]

    logger.info(
        "Running pre-flight check for %s",
        hostname,
    )

    dns_result = _check_dns(
        hostname
    )

    if not dns_result["success"]:

        logger.warning(
            "Target does not resolve: %s",
            hostname,
        )

        return {
            "status": "UNRESOLVED",
            "continue_recon": False,
            "dns": dns_result,
            "https": None,
            "http": None,
            "preferred_url": None,
            "message": (
                "Target does not resolve through DNS."
            ),
        }

    # HTTPS first

    https_result = _check_web(
        target["https_url"],
        timeout,
    )

    if https_result["responding"]:

        return {
            "status": "ACTIVE",
            "continue_recon": True,
            "dns": dns_result,
            "https": https_result,
            "http": None,
            "preferred_url":
                https_result["final_url"],
            "message":
                "Target is active over HTTPS.",
        }

    # HTTP fallback

    http_result = _check_web(
        target["http_url"],
        timeout,
    )

    if http_result["responding"]:

        return {
            "status": "ACTIVE",
            "continue_recon": True,
            "dns": dns_result,
            "https": https_result,
            "http": http_result,
            "preferred_url":
                http_result["final_url"],
            "message":
                "Target is active over HTTP.",
        }

    return {
        "status": "DNS_ONLY",
        "continue_recon": False,
        "dns": dns_result,
        "https": https_result,
        "http": http_result,
        "preferred_url": None,
        "message": (
            "Domain resolves, but no HTTP/HTTPS "
            "response was received."
        ),
    }