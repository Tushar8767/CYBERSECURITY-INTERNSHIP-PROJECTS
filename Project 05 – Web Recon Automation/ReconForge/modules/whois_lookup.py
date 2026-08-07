from datetime import date, datetime

import whois

from core.logger import setup_logger


logger = setup_logger("reconforge.whois")


def _normalize_value(value):
    """
    Convert WHOIS values into JSON/report-friendly values.

    WHOIS libraries may return:
    - strings
    - datetime objects
    - lists
    - None
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, list):
        return [
            _normalize_value(item)
            for item in value
        ]

    return str(value)


def _first_value(value):
    """
    Return the first item if WHOIS returned a list.

    Some WHOIS servers return multiple creation dates,
    expiry dates, or registrar-related values.
    """

    if isinstance(value, list):
        if not value:
            return None

        return value[0]

    return value


def _normalize_name_servers(value):
    """
    Normalize name-server output.

    Tasks:
    - Accept list/string values
    - Convert to lowercase
    - Remove trailing dots
    - Remove duplicates
    - Sort results
    """

    if not value:
        return []

    if not isinstance(value, list):
        value = [value]

    servers = set()

    for server in value:

        if not server:
            continue

        normalized = (
            str(server)
            .strip()
            .lower()
            .rstrip(".")
        )

        if normalized:
            servers.add(normalized)

    return sorted(servers)


def _normalize_status(value):
    """
    Normalize domain-status fields.

    Example values:
        clientTransferProhibited
        clientDeleteProhibited
    """

    if not value:
        return []

    if not isinstance(value, list):
        value = [value]

    statuses = []

    for status in value:

        if not status:
            continue

        cleaned = str(status).strip()

        if cleaned not in statuses:
            statuses.append(cleaned)

    return statuses


def _calculate_domain_age(creation_date):
    """
    Calculate approximate domain age in days.

    Returns None if the creation date is unavailable.
    """

    creation_date = _first_value(
        creation_date
    )

    if not creation_date:
        return None

    if isinstance(creation_date, date) and not isinstance(
        creation_date,
        datetime
    ):
        creation_date = datetime.combine(
            creation_date,
            datetime.min.time()
        )

    if not isinstance(
        creation_date,
        datetime
    ):
        return None

    now = datetime.now()

    # Remove timezone information only for calculation
    # if the library returned a timezone-aware datetime.
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(
            tzinfo=None
        )

    age = now - creation_date

    return max(
        age.days,
        0
    )


def lookup_whois(hostname):
    """
    Main WHOIS reconnaissance function.

    Collects:
    - domain name
    - registrar
    - WHOIS server
    - creation date
    - update date
    - expiry date
    - name servers
    - domain status
    - DNSSEC
    - registrant organization/country when available
    - approximate domain age

    WHOIS data may be hidden or unavailable due
    to registry privacy policies.
    """

    logger.info(
        "Starting WHOIS lookup for %s",
        hostname
    )

    try:

        result = whois.whois(
            hostname
        )

        creation_date_raw = getattr(
            result,
            "creation_date",
            None
        )

        updated_date_raw = getattr(
            result,
            "updated_date",
            None
        )

        expiration_date_raw = getattr(
            result,
            "expiration_date",
            None
        )

        creation_date = _first_value(
            creation_date_raw
        )

        updated_date = _first_value(
            updated_date_raw
        )

        expiration_date = _first_value(
            expiration_date_raw
        )

        name_servers = _normalize_name_servers(
            getattr(
                result,
                "name_servers",
                None
            )
        )

        domain_status = _normalize_status(
            getattr(
                result,
                "status",
                None
            )
        )

        data = {
            "domain_name": _normalize_value(
                getattr(
                    result,
                    "domain_name",
                    hostname
                )
            ),

            "registrar": _normalize_value(
                getattr(
                    result,
                    "registrar",
                    None
                )
            ),

            "whois_server": _normalize_value(
                getattr(
                    result,
                    "whois_server",
                    None
                )
            ),

            "creation_date": _normalize_value(
                creation_date
            ),

            "updated_date": _normalize_value(
                updated_date
            ),

            "expiration_date": _normalize_value(
                expiration_date
            ),

            "domain_age_days": _calculate_domain_age(
                creation_date
            ),

            "name_servers": name_servers,

            "status": domain_status,

            "dnssec": _normalize_value(
                getattr(
                    result,
                    "dnssec",
                    None
                )
            ),

            "registrant_organization": _normalize_value(
                getattr(
                    result,
                    "org",
                    None
                )
            ),

            "registrant_country": _normalize_value(
                getattr(
                    result,
                    "country",
                    None
                )
            ),
        }

        available_fields = sum(
            1
            for value in data.values()
            if value not in (
                None,
                [],
                "",
            )
        )

        status = "success"

        errors = []

        if available_fields <= 3:

            status = "partial"

            errors.append(
                "WHOIS returned limited information. "
                "The registry may restrict or redact domain data."
            )

        logger.info(
            "WHOIS lookup completed for %s with status %s",
            hostname,
            status
        )

        return {
            "module": "whois_lookup",
            "status": status,
            "data": data,
            "observations": [],
            "errors": errors,
        }

    except Exception as error:

        logger.warning(
            "WHOIS lookup failed for %s: %s",
            hostname,
            error
        )

        return {
            "module": "whois_lookup",
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [
                f"WHOIS lookup failed: {error}"
            ],
        }