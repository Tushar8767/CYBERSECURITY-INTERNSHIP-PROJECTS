import time
from typing import Dict, List, Any

import requests
from requests import Response
from requests.exceptions import (
    ConnectionError,
    InvalidURL,
    RequestException,
    SSLError,
    Timeout,
)

from core.logger import setup_logger


logger = setup_logger("reconforge.http")


DEFAULT_USER_AGENT = (
    "ReconForge/1.0 "
    "(Authorized Web Reconnaissance Framework)"
)


def _extract_redirect_chain(response: Response) -> List[Dict[str, Any]]:
    """
    Convert requests redirect history into serializable data.
    """

    redirects = []

    for redirect_response in response.history:
        redirects.append(
            {
                "status_code": redirect_response.status_code,
                "url": redirect_response.url,
                "location": redirect_response.headers.get("Location"),
            }
        )

    return redirects


def _extract_headers(response: Response) -> Dict[str, str]:
    """
    Convert HTTP headers into a normal dictionary.
    """

    return {
        str(key): str(value)
        for key, value in response.headers.items()
    }


def fetch_http_information(
    url: str,
    timeout: float = 10.0
) -> dict:
    """
    Fetch basic HTTP information from an authorized target.

    Collects:
    - status code
    - final URL
    - redirect chain
    - response headers
    - server banner
    - content type
    - content length
    - response time
    """

    logger.info("Starting HTTP reconnaissance for %s", url)

    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
    }

    start_time = time.perf_counter()

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )

        duration_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        response_headers = _extract_headers(response)

        content_length = response_headers.get(
            "Content-Length"
        )

        try:
            content_length = (
                int(content_length)
                if content_length is not None
                else None
            )
        except ValueError:
            content_length = None

        data = {
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "reason": response.reason,
            "redirect_count": len(response.history),
            "redirects": _extract_redirect_chain(response),
            "headers": response_headers,
            "server": response_headers.get("Server"),
            "x_powered_by": response_headers.get("X-Powered-By"),
            "content_type": response_headers.get("Content-Type"),
            "content_length": content_length,
            "response_time_ms": duration_ms,
            "https": response.url.lower().startswith("https://"),
        }

        logger.info(
            "HTTP reconnaissance completed for %s: status=%s",
            url,
            response.status_code,
        )

        response.close()

        return {
            "module": "http_headers",
            "status": "success",
            "data": data,
            "errors": [],
        }

    except Timeout:
        error_message = (
            f"HTTP request timed out after {timeout} seconds."
        )

        logger.warning(
            "%s Target: %s",
            error_message,
            url,
        )

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [error_message],
        }

    except SSLError as error:
        error_message = (
            f"TLS/SSL validation failed: {error}"
        )

        logger.warning(
            "SSL error while requesting %s",
            url,
        )

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [error_message],
        }

    except InvalidURL:
        error_message = (
            f"Invalid URL supplied: {url}"
        )

        logger.warning(error_message)

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [error_message],
        }

    except ConnectionError as error:
        error_message = (
            f"Unable to connect to target: {error}"
        )

        logger.warning(
            "Connection failed for %s",
            url,
        )

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [error_message],
        }

    except RequestException as error:
        error_message = (
            f"HTTP request failed: {error}"
        )

        logger.warning(
            "HTTP request failed for %s",
            url,
        )

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [error_message],
        }

    except Exception as error:
        logger.exception(
            "Unexpected HTTP reconnaissance error for %s",
            url,
        )

        return {
            "module": "http_headers",
            "status": "failed",
            "data": {},
            "errors": [
                f"Unexpected HTTP error: {error}"
            ],
        }