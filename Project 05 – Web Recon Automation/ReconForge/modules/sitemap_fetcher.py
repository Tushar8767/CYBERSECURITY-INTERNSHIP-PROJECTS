import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests

from core.logger import setup_logger


logger = setup_logger("reconforge.sitemap")


DEFAULT_USER_AGENT = (
    "ReconForge/1.0 "
    "(Authorized Web Reconnaissance Framework)"
)

DEFAULT_SITEMAP_PATHS = [
    "sitemap.xml",
    "sitemap_index.xml",
]

MAX_URLS = 500


def _build_candidate_urls(base_url, robots_result=None):
    """
    Build sitemap URLs to test.

    Task:
    - Reuse Sitemap directives from robots.txt
    - Add common sitemap locations
    - Remove duplicates
    """

    candidates = []

    if robots_result:
        data = robots_result.get("data", {})
        parsed = data.get("parsed", {})

        for sitemap_url in parsed.get("sitemaps", []):
            if sitemap_url not in candidates:
                candidates.append(sitemap_url)

    for path in DEFAULT_SITEMAP_PATHS:

        url = urljoin(
            base_url.rstrip("/") + "/",
            path,
        )

        if url not in candidates:
            candidates.append(url)

    return candidates


def _remove_xml_namespace(tag):
    """
    Remove an XML namespace from a tag.

    Example:
        {http://www.sitemaps.org/schemas/sitemap/0.9}url

    becomes:
        url
    """

    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


def _parse_xml(content):
    """
    Parse sitemap XML content.

    Detects:
    - normal URL sitemap
    - sitemap index

    Returns:
    - discovered page URLs
    - nested sitemap URLs
    """

    page_urls = []
    nested_sitemaps = []

    root = ET.fromstring(content)

    root_type = _remove_xml_namespace(
        root.tag
    )

    for element in root.iter():

        tag = _remove_xml_namespace(
            element.tag
        )

        if tag != "loc":
            continue

        if not element.text:
            continue

        value = element.text.strip()

        if not value:
            continue

        if root_type == "urlset":

            if (
                value not in page_urls
                and len(page_urls) < MAX_URLS
            ):
                page_urls.append(value)

        elif root_type == "sitemapindex":

            if value not in nested_sitemaps:
                nested_sitemaps.append(value)

    return {
        "type": root_type,
        "urls": page_urls,
        "nested_sitemaps": nested_sitemaps,
    }


def _fetch_single_sitemap(
    sitemap_url,
    timeout=10.0
):
    """
    Fetch and parse one sitemap.

    Task:
    - Request sitemap
    - Validate HTTP status
    - Parse XML
    - Return structured result
    """

    logger.info(
        "Fetching sitemap %s",
        sitemap_url
    )

    try:

        response = requests.get(
            sitemap_url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": DEFAULT_USER_AGENT
            },
        )

        if response.status_code == 404:

            return {
                "status": "not_found",
                "requested_url": sitemap_url,
                "final_url": response.url,
                "status_code": 404,
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "type": None,
                "urls": [],
                "nested_sitemaps": [],
                "error": None,
            }

        response.raise_for_status()

        parsed = _parse_xml(
            response.text
        )

        return {
            "status": "success",
            "requested_url": sitemap_url,
            "final_url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type"
            ),
            "type": parsed["type"],
            "urls": parsed["urls"],
            "nested_sitemaps": parsed[
                "nested_sitemaps"
            ],
            "error": None,
        }

    except ET.ParseError as error:

        return {
            "status": "failed",
            "requested_url": sitemap_url,
            "final_url": None,
            "status_code": None,
            "content_type": None,
            "type": None,
            "urls": [],
            "nested_sitemaps": [],
            "error": (
                f"Invalid sitemap XML: {error}"
            ),
        }

    except requests.Timeout:

        return {
            "status": "failed",
            "requested_url": sitemap_url,
            "final_url": None,
            "status_code": None,
            "content_type": None,
            "type": None,
            "urls": [],
            "nested_sitemaps": [],
            "error": (
                f"Sitemap request timed out "
                f"after {timeout} seconds."
            ),
        }

    except requests.RequestException as error:

        return {
            "status": "failed",
            "requested_url": sitemap_url,
            "final_url": None,
            "status_code": None,
            "content_type": None,
            "type": None,
            "urls": [],
            "nested_sitemaps": [],
            "error": (
                f"Sitemap request failed: {error}"
            ),
        }


def _collect_nested_sitemaps(
    sitemap_urls,
    timeout=10.0
):
    """
    Fetch nested sitemaps discovered inside a sitemap index.

    Task:
    - Follow sitemap-index references
    - Collect page URLs
    - Avoid duplicate sitemap processing
    - Respect MAX_URLS
    """

    visited = set()
    discovered_urls = []
    sitemap_results = []

    queue = list(
        sitemap_urls
    )

    while queue:

        sitemap_url = queue.pop(0)

        if sitemap_url in visited:
            continue

        visited.add(
            sitemap_url
        )

        result = _fetch_single_sitemap(
            sitemap_url,
            timeout,
        )

        sitemap_results.append(
            result
        )

        if result["status"] != "success":
            continue

        for url in result["urls"]:

            if url not in discovered_urls:
                discovered_urls.append(url)

            if len(discovered_urls) >= MAX_URLS:
                break

        if len(discovered_urls) >= MAX_URLS:
            break

        for nested in result[
            "nested_sitemaps"
        ]:

            if (
                nested not in visited
                and nested not in queue
            ):
                queue.append(nested)

    return {
        "urls": discovered_urls,
        "sitemaps": sitemap_results,
    }


def _create_observations(
    discovered_urls,
    sitemap_count
):
    """
    Create informational sitemap observations.

    Sitemap discovery is reconnaissance data,
    not automatically a vulnerability.
    """

    observations = []

    if discovered_urls:

        observations.append(
            {
                "title": "Sitemap exposes application URL structure",
                "severity": "Informational",
                "evidence": (
                    f"{len(discovered_urls)} URL(s) "
                    f"discovered across "
                    f"{sitemap_count} sitemap(s)."
                ),
                "description": (
                    "Sitemap files reveal publicly indexed "
                    "application routes and content structure."
                ),
                "recommendation": (
                    "Review sitemap contents and avoid publishing "
                    "URLs that should not be publicly discoverable."
                ),
            }
        )

    return observations


def fetch_sitemaps(
    base_url,
    robots_result=None,
    timeout=10.0
):
    """
    Main sitemap reconnaissance controller.

    Collects:
    - sitemap URLs
    - sitemap type
    - nested sitemap references
    - discovered website URLs
    """

    logger.info(
        "Starting sitemap discovery for %s",
        base_url
    )

    candidates = _build_candidate_urls(
        base_url,
        robots_result,
    )

    candidate_results = []
    discovered_sitemaps = []

    errors = []

    for candidate in candidates:

        result = _fetch_single_sitemap(
            candidate,
            timeout,
        )

        candidate_results.append(
            result
        )

        if result["status"] == "success":

            discovered_sitemaps.append(
                result["final_url"]
                or candidate
            )

            for nested in result[
                "nested_sitemaps"
            ]:

                if nested not in discovered_sitemaps:
                    discovered_sitemaps.append(
                        nested
                    )

        elif result["status"] == "failed":

            if result["error"]:
                errors.append(
                    f"{candidate}: "
                    f"{result['error']}"
                )

    if not discovered_sitemaps:

        logger.info(
            "No sitemap discovered for %s",
            base_url
        )

        return {
            "module": "sitemap_fetcher",
            "status": "success",
            "data": {
                "exists": False,
                "candidate_results": candidate_results,
                "sitemaps": [],
                "urls": [],
                "total_urls": 0,
            },
            "observations": [],
            "errors": errors,
        }

    collection = _collect_nested_sitemaps(
        discovered_sitemaps,
        timeout,
    )

    observations = _create_observations(
        collection["urls"],
        len(collection["sitemaps"]),
    )

    status = (
        "partial"
        if errors
        else "success"
    )

    logger.info(
        "Sitemap discovery completed with "
        "%d URL(s)",
        len(collection["urls"])
    )

    return {
        "module": "sitemap_fetcher",
        "status": status,
        "data": {
            "exists": True,
            "candidate_results": candidate_results,
            "sitemaps": collection["sitemaps"],
            "urls": collection["urls"],
            "total_urls": len(
                collection["urls"]
            ),
        },
        "observations": observations,
        "errors": errors,
    }