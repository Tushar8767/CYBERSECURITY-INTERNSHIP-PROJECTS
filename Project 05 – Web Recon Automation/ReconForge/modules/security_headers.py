from core.logger import setup_logger


logger = setup_logger("reconforge.security_headers")


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": (
            "Helps restrict which scripts, styles, images, and other "
            "resources the browser is allowed to load."
        ),
        "recommendation": (
            "Implement and test a restrictive Content-Security-Policy."
        ),
    },

    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": (
            "Forces supported browsers to use HTTPS for future requests."
        ),
        "recommendation": (
            "Configure Strict-Transport-Security after confirming "
            "that the application fully supports HTTPS."
        ),
    },

    "X-Frame-Options": {
        "severity": "Medium",
        "description": (
            "Helps prevent the website from being embedded inside "
            "unauthorized frames."
        ),
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use the "
            "CSP frame-ancestors directive."
        ),
    },

    "X-Content-Type-Options": {
        "severity": "Low",
        "description": (
            "Prevents browsers from MIME-sniffing content into "
            "unexpected file types."
        ),
        "recommendation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },

    "Referrer-Policy": {
        "severity": "Low",
        "description": (
            "Controls how much referrer information is sent with requests."
        ),
        "recommendation": (
            "Configure an appropriate Referrer-Policy such as "
            "strict-origin-when-cross-origin."
        ),
    },

    "Permissions-Policy": {
        "severity": "Low",
        "description": (
            "Controls access to selected browser capabilities and APIs."
        ),
        "recommendation": (
            "Define a Permissions-Policy appropriate for the application."
        ),
    },

    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "description": (
            "Helps isolate the browsing context from cross-origin documents."
        ),
        "recommendation": (
            "Consider configuring Cross-Origin-Opener-Policy."
        ),
    },

    "Cross-Origin-Resource-Policy": {
        "severity": "Low",
        "description": (
            "Controls whether cross-origin websites can load resources."
        ),
        "recommendation": (
            "Consider configuring Cross-Origin-Resource-Policy."
        ),
    },
}


def _normalize_headers(headers: dict) -> dict:
    """
    Convert header names to lowercase.

    This makes header lookup case-insensitive because HTTP header
    names should not be treated as case-sensitive.
    """

    return {
        str(name).lower(): str(value)
        for name, value in headers.items()
    }


def _create_observation(
    observation_id: str,
    title: str,
    severity: str,
    evidence: str,
    description: str,
    recommendation: str,
) -> dict:
    """
    Create one observation using a consistent structure.
    """

    return {
        "id": observation_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "description": description,
        "recommendation": recommendation,
    }


def _check_missing_security_headers(
    headers: dict,
    is_https: bool
) -> list:
    """
    Check whether important browser security headers are missing.
    """

    observations = []
    observation_number = 1

    for header_name, details in SECURITY_HEADERS.items():

        normalized_name = header_name.lower()

        # HSTS is meaningful only for HTTPS websites.
        if (
            header_name == "Strict-Transport-Security"
            and not is_https
        ):
            continue

        if normalized_name not in headers:

            observation = _create_observation(
                observation_id=f"RF-{observation_number:03}",
                title=f"{header_name} header not detected",
                severity=details["severity"],
                evidence=f"Missing HTTP response header: {header_name}",
                description=details["description"],
                recommendation=details["recommendation"],
            )

            observations.append(observation)

            observation_number += 1

    return observations


def _check_server_disclosure(
    headers: dict,
    start_number: int
) -> list:
    """
    Detect server technology information exposed by response headers.
    """

    observations = []
    observation_number = start_number

    server = headers.get("server")

    if server:
        observations.append(
            _create_observation(
                observation_id=f"RF-{observation_number:03}",
                title="Server banner exposed",
                severity="Low",
                evidence=f"Server: {server}",
                description=(
                    "The HTTP response exposes information about "
                    "the web server technology."
                ),
                recommendation=(
                    "Minimize unnecessary server product or version "
                    "information in HTTP response headers."
                ),
            )
        )

        observation_number += 1

    powered_by = headers.get("x-powered-by")

    if powered_by:
        observations.append(
            _create_observation(
                observation_id=f"RF-{observation_number:03}",
                title="Application technology disclosed",
                severity="Low",
                evidence=f"X-Powered-By: {powered_by}",
                description=(
                    "The response exposes application framework or "
                    "technology information."
                ),
                recommendation=(
                    "Disable unnecessary X-Powered-By headers."
                ),
            )
        )

    return observations


def _parse_set_cookie(headers: dict) -> list:
    """
    Extract cookie strings from the Set-Cookie header.

    This is a basic parser suitable for the current project stage.
    """

    set_cookie = headers.get("set-cookie")

    if not set_cookie:
        return []

    return [set_cookie]


def _check_cookie_security(
    headers: dict,
    is_https: bool,
    start_number: int
) -> list:
    """
    Check basic cookie protection flags:
    - Secure
    - HttpOnly
    - SameSite
    """

    observations = []
    observation_number = start_number

    cookies = _parse_set_cookie(headers)

    for index, cookie in enumerate(cookies, start=1):

        cookie_lower = cookie.lower()

        cookie_name = cookie.split("=", 1)[0].strip()

        if is_https and "secure" not in cookie_lower:
            observations.append(
                _create_observation(
                    observation_id=f"RF-{observation_number:03}",
                    title="Cookie missing Secure flag",
                    severity="Medium",
                    evidence=f"Cookie: {cookie_name}",
                    description=(
                        "A cookie delivered over HTTPS does not appear "
                        "to use the Secure attribute."
                    ),
                    recommendation=(
                        "Add the Secure attribute to cookies that should "
                        "only be transmitted over HTTPS."
                    ),
                )
            )

            observation_number += 1

        if "httponly" not in cookie_lower:
            observations.append(
                _create_observation(
                    observation_id=f"RF-{observation_number:03}",
                    title="Cookie missing HttpOnly flag",
                    severity="Medium",
                    evidence=f"Cookie: {cookie_name}",
                    description=(
                        "The cookie does not appear to use the HttpOnly "
                        "attribute."
                    ),
                    recommendation=(
                        "Apply HttpOnly to cookies that do not require "
                        "JavaScript access."
                    ),
                )
            )

            observation_number += 1

        if "samesite" not in cookie_lower:
            observations.append(
                _create_observation(
                    observation_id=f"RF-{observation_number:03}",
                    title="Cookie missing SameSite attribute",
                    severity="Low",
                    evidence=f"Cookie: {cookie_name}",
                    description=(
                        "The cookie does not explicitly define a "
                        "SameSite policy."
                    ),
                    recommendation=(
                        "Set an appropriate SameSite value such as "
                        "Lax or Strict where compatible."
                    ),
                )
            )

            observation_number += 1

    return observations


def analyze_security_headers(http_result: dict) -> dict:
    """
    Analyze HTTP reconnaissance results and identify basic
    security configuration observations.
    """

    logger.info("Starting security header analysis")

    if not http_result:
        return {
            "module": "security_headers",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": ["HTTP result was not provided."],
        }

    if http_result.get("status") != "success":
        return {
            "module": "security_headers",
            "status": "skipped",
            "data": {},
            "observations": [],
            "errors": [
                "Security header analysis skipped because "
                "HTTP reconnaissance did not succeed."
            ],
        }

    http_data = http_result.get("data", {})

    original_headers = http_data.get("headers", {})

    normalized_headers = _normalize_headers(
        original_headers
    )

    is_https = bool(
        http_data.get("https", False)
    )

    observations = []

    missing_headers = _check_missing_security_headers(
        normalized_headers,
        is_https,
    )

    observations.extend(missing_headers)

    next_number = len(observations) + 1

    disclosure_observations = _check_server_disclosure(
        normalized_headers,
        next_number,
    )

    observations.extend(
        disclosure_observations
    )

    next_number = len(observations) + 1

    cookie_observations = _check_cookie_security(
        normalized_headers,
        is_https,
        next_number,
    )

    observations.extend(
        cookie_observations
    )

    severity_summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for observation in observations:
        severity = observation["severity"]

        if severity in severity_summary:
            severity_summary[severity] += 1

    logger.info(
        "Security header analysis completed with %d observation(s)",
        len(observations),
    )

    return {
        "module": "security_headers",
        "status": "success",
        "data": {
            "checked_headers": list(
                SECURITY_HEADERS.keys()
            ),
            "severity_summary": severity_summary,
            "total_observations": len(observations),
        },
        "observations": observations,
        "errors": [],
    }