import requests
from urllib.parse import urljoin

from core.logger import setup_logger


logger = setup_logger("reconforge.robots")


DEFAULT_USER_AGENT = (
    "ReconForge/1.0 "
    "(Authorized Web Reconnaissance Framework)"
)


def _build_robots_url(base_url):
    """
    Build the standard robots.txt URL.

    Task:
    - Accept normalized base URL
    - Return:
        https://example.com/robots.txt
    """

    return urljoin(
        base_url.rstrip("/") + "/",
        "robots.txt"
    )


def _parse_robots_content(content):
    """
    Parse basic robots.txt directives.

    Task:
    - Extract User-agent entries
    - Extract Disallow paths
    - Extract Allow paths
    - Extract Sitemap references

    This is intentionally lightweight and readable.
    """

    user_agents = []
    disallow_paths = []
    allow_paths = []
    sitemaps = []

    for raw_line in content.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        # Ignore comments.
        if line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1
        )

        key = key.strip().lower()
        value = value.strip()

        if not value:
            continue

        if key == "user-agent":
            if value not in user_agents:
                user_agents.append(value)

        elif key == "disallow":
            if value not in disallow_paths:
                disallow_paths.append(value)

        elif key == "allow":
            if value not in allow_paths:
                allow_paths.append(value)

        elif key == "sitemap":
            if value not in sitemaps:
                sitemaps.append(value)

    return {
        "user_agents": user_agents,
        "disallow_paths": disallow_paths,
        "allow_paths": allow_paths,
        "sitemaps": sitemaps,
    }


def _create_observations(parsed_data):
    """
    Create informational observations from robots.txt.

    Task:
    - Report discovered paths as recon information
    - Avoid calling them vulnerabilities
    """

    observations = []

    disallowed = parsed_data.get(
        "disallow_paths",
        []
    )

    if disallowed:

        observations.append(
            {
                "title": "robots.txt exposes disallowed paths",
                "severity": "Informational",
                "evidence": (
                    f"{len(disallowed)} "
                    f"Disallow directive(s) detected."
                ),
                "description": (
                    "The robots.txt file exposes paths that may "
                    "help authorized testers understand the "
                    "website structure. These paths are not "
                    "automatically sensitive or vulnerable."
                ),
                "recommendation": (
                    "Review whether robots.txt unnecessarily "
                    "advertises administrative or sensitive-looking "
                    "paths. Do not rely on robots.txt as an access "
                    "control mechanism."
                ),
            }
        )

    return observations


def fetch_robots_txt(
    base_url,
    timeout=10.0
):
    """
    Main robots.txt collection controller.

    Collects:
    - robots.txt URL
    - HTTP status
    - content type
    - raw content
    - User-agent directives
    - Disallow paths
    - Allow paths
    - Sitemap references
    """

    robots_url = _build_robots_url(
        base_url
    )

    logger.info(
        "Starting robots.txt collection for %s",
        robots_url
    )

    try:

        response = requests.get(
            robots_url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": DEFAULT_USER_AGENT
            },
        )

        status_code = response.status_code

        if status_code == 404:

            logger.info(
                "robots.txt not found for %s",
                base_url
            )

            return {
                "module": "robots_fetcher",
                "status": "success",
                "data": {
                    "robots_url": robots_url,
                    "final_url": response.url,
                    "status_code": status_code,
                    "exists": False,
                    "content_type": response.headers.get(
                        "Content-Type"
                    ),
                    "content": None,
                    "parsed": {
                        "user_agents": [],
                        "disallow_paths": [],
                        "allow_paths": [],
                        "sitemaps": [],
                    },
                },
                "observations": [],
                "errors": [],
            }

        response.raise_for_status()

        content = response.text

        parsed_data = _parse_robots_content(
            content
        )

        observations = _create_observations(
            parsed_data
        )

        logger.info(
            "robots.txt collection completed "
            "with %d disallow path(s)",
            len(
                parsed_data[
                    "disallow_paths"
                ]
            )
        )

        return {
            "module": "robots_fetcher",
            "status": "success",
            "data": {
                "robots_url": robots_url,
                "final_url": response.url,
                "status_code": status_code,
                "exists": True,
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "content": content,
                "parsed": parsed_data,
            },
            "observations": observations,
            "errors": [],
        }

    except requests.Timeout:

        message = (
            f"robots.txt request timed out "
            f"after {timeout} seconds."
        )

        logger.warning(
            "%s URL: %s",
            message,
            robots_url
        )

        return {
            "module": "robots_fetcher",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except requests.RequestException as error:

        message = (
            f"robots.txt request failed: {error}"
        )

        logger.warning(
            "%s",
            message
        )

        return {
            "module": "robots_fetcher",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [message],
        }

    except Exception as error:

        logger.exception(
            "Unexpected robots.txt error for %s",
            base_url
        )

        return {
            "module": "robots_fetcher",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [
                f"Unexpected robots.txt error: {error}"
            ],
        }