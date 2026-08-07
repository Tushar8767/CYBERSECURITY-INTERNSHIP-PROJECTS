import dns.resolver
import dns.exception

from core.logger import setup_logger


logger = setup_logger("reconforge.dns")


DNS_RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
]


def _record_to_string(record_type: str, record) -> str:
    """
    Convert DNS record objects into clean strings.
    """

    if record_type == "MX":
        return f"{record.preference} {record.exchange}".rstrip(".")

    if record_type == "SOA":
        return (
            f"{record.mname} "
            f"{record.rname} "
            f"{record.serial} "
            f"{record.refresh} "
            f"{record.retry} "
            f"{record.expire} "
            f"{record.minimum}"
        )

    if record_type == "TXT":
        try:
            return "".join(
                part.decode("utf-8", errors="replace")
                for part in record.strings
            )
        except AttributeError:
            return record.to_text().strip('"')

    return record.to_text().rstrip(".")


def lookup_dns(
    hostname: str,
    timeout: float = 5.0
) -> dict:
    """
    Collect common DNS records for a hostname.

    The function handles individual record failures and continues
    instead of terminating the whole reconnaissance process.
    """

    logger.info("Starting DNS lookup for %s", hostname)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = {}
    errors = []

    for record_type in DNS_RECORD_TYPES:

        try:
            answers = resolver.resolve(
                hostname,
                record_type,
                raise_on_no_answer=False
            )

            if answers.rrset is None:
                records[record_type] = []

                logger.debug(
                    "No %s records found for %s",
                    record_type,
                    hostname
                )

                continue

            values = []

            for answer in answers:
                value = _record_to_string(
                    record_type,
                    answer
                )

                values.append(value)

            records[record_type] = values

            logger.info(
                "Collected %d %s record(s) for %s",
                len(values),
                record_type,
                hostname
            )

        except dns.resolver.NXDOMAIN:
            error_message = (
                f"Domain does not exist: {hostname}"
            )

            logger.warning(error_message)

            return {
                "module": "dns_lookup",
                "status": "failed",
                "data": {},
                "errors": [error_message],
            }

        except dns.resolver.NoNameservers:
            error_message = (
                f"No available nameservers for {hostname}"
            )

            logger.warning(error_message)

            records[record_type] = []
            errors.append(error_message)

        except dns.resolver.LifetimeTimeout:
            error_message = (
                f"DNS timeout while requesting "
                f"{record_type} records"
            )

            logger.warning(
                "%s for %s",
                error_message,
                hostname
            )

            records[record_type] = []
            errors.append(error_message)

        except dns.exception.DNSException as error:
            error_message = (
                f"{record_type} lookup failed: {error}"
            )

            logger.warning(
                "%s",
                error_message
            )

            records[record_type] = []
            errors.append(error_message)

        except Exception as error:
            error_message = (
                f"Unexpected {record_type} lookup error: {error}"
            )

            logger.exception(error_message)

            records[record_type] = []
            errors.append(error_message)

    status = "success"

    if errors:
        status = "partial"

    logger.info(
        "DNS lookup completed for %s with status %s",
        hostname,
        status
    )

    return {
        "module": "dns_lookup",
        "status": status,
        "data": {
            "hostname": hostname,
            "records": records,
        },
        "errors": errors,
    }