import argparse

from core.logger import setup_logger
from core.target import normalize_target, TargetValidationError

from core.preflight import (
    check_target_availability,
)


from modules.dns_lookup import lookup_dns
from modules.http_headers import fetch_http_information
from modules.security_headers import analyze_security_headers
from modules.tls_certificate import inspect_tls_certificate
from modules.whois_lookup import lookup_whois
from modules.ip_lookup import lookup_ip_information
from modules.robots_fetcher import fetch_robots_txt
from modules.sitemap_fetcher import fetch_sitemaps

from reporting.json_report import (
    build_scan_result,
    save_json_report,
)

logger = setup_logger()


def parse_arguments():
    """
    Parse command-line arguments supplied to ReconForge.

    Example:
        python main.py --target example.com
    """

    parser = argparse.ArgumentParser(
        description="ReconForge - Authorized Web Reconnaissance Framework"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Authorized target domain or website URL"
    )

    return parser.parse_args()


def print_target_information(target):
    """
    Display normalized target information.
    """

    print("\n[+] Target received successfully.\n")

    print(f"Original Input : {target['original']}")
    print(f"Hostname       : {target['hostname']}")
    print(f"HTTPS URL      : {target['https_url']}")
    print(f"HTTP URL       : {target['http_url']}")


def print_dns_results(dns_result):
    """
    Display DNS reconnaissance results.
    """

    print("\n[+] DNS Reconnaissance\n")

    print(f"Status: {dns_result['status']}")

    if dns_result["data"]:

        records = dns_result["data"]["records"]

        for record_type, values in records.items():

            print(f"\n{record_type} Records:")

            if not values:
                print("  No records found")
                continue

            for value in values:
                print(f"  {value}")

    if dns_result["errors"]:

        print("\nDNS Warnings:")

        for error in dns_result["errors"]:
            print(f"  - {error}")


def print_http_results(http_result):
    """
    Display HTTP reconnaissance information.
    """

    print("\n[+] HTTP Reconnaissance\n")

    print(f"Status: {http_result['status']}")

    if http_result["data"]:

        data = http_result["data"]

        print(f"Requested URL    : {data['requested_url']}")
        print(f"Final URL        : {data['final_url']}")
        print(f"Status Code      : {data['status_code']}")
        print(f"Reason           : {data['reason']}")
        print(f"Redirects        : {data['redirect_count']}")
        print(f"Response Time    : {data['response_time_ms']} ms")

        print(
            f"Server           : "
            f"{data['server'] or 'Not disclosed'}"
        )

        print(
            f"X-Powered-By     : "
            f"{data['x_powered_by'] or 'Not disclosed'}"
        )

        print(
            f"Content-Type     : "
            f"{data['content_type'] or 'Not provided'}"
        )

        print(
            f"Content-Length   : "
            f"{data['content_length'] if data['content_length'] is not None else 'Unknown'}"
        )

        if data["redirects"]:

            print("\nRedirect Chain:")

            for redirect in data["redirects"]:

                print(
                    f"  {redirect['status_code']} "
                    f"{redirect['url']} "
                    f"-> {redirect['location']}"
                )

        print("\nHTTP Headers:")

        for name, value in data["headers"].items():
            print(f"  {name}: {value}")

    if http_result["errors"]:

        print("\nHTTP Warnings:")

        for error in http_result["errors"]:
            print(f"  - {error}")


def print_security_results(security_result):
    """
    Display security header observations and severity summary.
    """

    print("\n[+] Security Header Analysis\n")

    print(
        f"Status             : "
        f"{security_result['status']}"
    )

    if security_result["data"]:

        summary = security_result["data"]["severity_summary"]

        print(
            f"Total Observations : "
            f"{security_result['data']['total_observations']}"
        )

        print("\nSeverity Summary:")

        print(f"  High          : {summary['High']}")
        print(f"  Medium        : {summary['Medium']}")
        print(f"  Low           : {summary['Low']}")
        print(f"  Informational : {summary['Informational']}")

    if security_result["observations"]:

        print("\nObservations:")

        for observation in security_result["observations"]:

            print(
                f"\n[{observation['id']}] "
                f"{observation['title']}"
            )

            print(
                f"Severity       : "
                f"{observation['severity']}"
            )

            print(
                f"Evidence       : "
                f"{observation['evidence']}"
            )

            print(
                f"Description    : "
                f"{observation['description']}"
            )

            print(
                f"Recommendation : "
                f"{observation['recommendation']}"
            )

    if security_result["errors"]:

        print("\nSecurity Analysis Warnings:")

        for error in security_result["errors"]:
            print(f"  - {error}")

def print_whois_results(whois_result):
    """
    Display WHOIS reconnaissance results.
    """

    print("\n[+] WHOIS Reconnaissance\n")

    print(
        f"Status              : "
        f"{whois_result['status']}"
    )

    if whois_result["data"]:

        data = whois_result["data"]

        print(
            f"Domain Name         : "
            f"{data['domain_name'] or 'Unavailable'}"
        )

        print(
            f"Registrar           : "
            f"{data['registrar'] or 'Unavailable'}"
        )

        print(
            f"WHOIS Server        : "
            f"{data['whois_server'] or 'Unavailable'}"
        )

        print(
            f"Creation Date       : "
            f"{data['creation_date'] or 'Unavailable'}"
        )

        print(
            f"Updated Date        : "
            f"{data['updated_date'] or 'Unavailable'}"
        )

        print(
            f"Expiration Date     : "
            f"{data['expiration_date'] or 'Unavailable'}"
        )

        print(
            f"Domain Age (days)   : "
            f"{data['domain_age_days'] if data['domain_age_days'] is not None else 'Unknown'}"
        )

        print(
            f"DNSSEC              : "
            f"{data['dnssec'] or 'Unavailable'}"
        )

        print(
            f"Registrant Org      : "
            f"{data['registrant_organization'] or 'Unavailable'}"
        )

        print(
            f"Registrant Country  : "
            f"{data['registrant_country'] or 'Unavailable'}"
        )

        print("\nName Servers:")

        if data["name_servers"]:

            for server in data[
                "name_servers"
            ]:

                print(
                    f"  {server}"
                )

        else:
            print(
                "  No name-server data available"
            )

        print("\nDomain Status:")

        if data["status"]:

            for status in data[
                "status"
            ]:

                print(
                    f"  {status}"
                )

        else:
            print(
                "  No status data available"
            )

    if whois_result["errors"]:

        print("\nWHOIS Warnings:")

        for error in whois_result[
            "errors"
        ]:

            print(
                f"  - {error}"
            )
def print_ip_results(ip_result):
    """
    Display IP reconnaissance results.
    """

    print("\n[+] IP Information\n")

    print(
        f"Status: {ip_result['status']}"
    )

    if ip_result["data"]:

        results = ip_result[
            "data"
        ]["results"]

        if not results:
            print(
                "No IP information available."
            )

        for result in results:

            print(
                "\n--------------------------------"
            )

            print(
                f"IP Address : "
                f"{result['ip_address']}"
            )

            classification = result[
                "classification"
            ]

            print(
                f"Version    : "
                f"{classification['version'] or 'Unknown'}"
            )

            print(
                f"Public     : "
                f"{'Yes' if classification['public'] else 'No'}"
            )

            print(
                f"Private    : "
                f"{'Yes' if classification['private'] else 'No'}"
            )

            print(
                f"Loopback   : "
                f"{'Yes' if classification['loopback'] else 'No'}"
            )

            reverse_dns = result[
                "reverse_dns"
            ]

            if reverse_dns:

                print(
                    f"Reverse DNS: "
                    f"{reverse_dns['hostname']}"
                )

            else:
                print(
                    "Reverse DNS: Unavailable"
                )

            geo = result[
                "geolocation"
            ]

            print(
                f"Geo Status : "
                f"{geo['status']}"
            )

            if geo["data"]:

                data = geo["data"]

                print(
                    f"Country    : "
                    f"{data['country'] or 'Unknown'}"
                )

                print(
                    f"Region     : "
                    f"{data['region'] or 'Unknown'}"
                )

                print(
                    f"City       : "
                    f"{data['city'] or 'Unknown'}"
                )

                print(
                    f"ASN        : "
                    f"{data['asn'] or 'Unknown'}"
                )

                print(
                    f"Organization: "
                    f"{data['organization'] or 'Unknown'}"
                )

                print(
                    f"ISP        : "
                    f"{data['isp'] or 'Unknown'}"
                )

    if ip_result["errors"]:

        print("\nIP Warnings:")

        for error in ip_result[
            "errors"
        ]:

            print(
                f"  - {error}"
            )
def print_robots_results(robots_result):
    """
    Display robots.txt reconnaissance results.
    """

    print("\n[+] robots.txt Analysis\n")

    print(
        f"Status: {robots_result['status']}"
    )

    if robots_result["data"]:

        data = robots_result["data"]

        print(
            f"URL         : {data['robots_url']}"
        )

        print(
            f"Final URL   : {data['final_url']}"
        )

        print(
            f"HTTP Status : {data['status_code']}"
        )

        print(
            f"Exists      : "
            f"{'Yes' if data['exists'] else 'No'}"
        )

        if data["exists"]:

            parsed = data["parsed"]

            print("\nUser Agents:")

            if parsed["user_agents"]:

                for value in parsed[
                    "user_agents"
                ]:
                    print(
                        f"  {value}"
                    )

            else:
                print(
                    "  None detected"
                )

            print("\nDisallow Paths:")

            if parsed["disallow_paths"]:

                for value in parsed[
                    "disallow_paths"
                ]:
                    print(
                        f"  {value}"
                    )

            else:
                print(
                    "  None detected"
                )

            print("\nAllow Paths:")

            if parsed["allow_paths"]:

                for value in parsed[
                    "allow_paths"
                ]:
                    print(
                        f"  {value}"
                    )

            else:
                print(
                    "  None detected"
                )

            print("\nSitemap References:")

            if parsed["sitemaps"]:

                for value in parsed[
                    "sitemaps"
                ]:
                    print(
                        f"  {value}"
                    )

            else:
                print(
                    "  None detected"
                )

    if robots_result["observations"]:

        print("\nrobots.txt Observations:")

        for observation in robots_result[
            "observations"
        ]:

            print(
                f"\n{observation['title']}"
            )

            print(
                f"Severity       : "
                f"{observation['severity']}"
            )

            print(
                f"Evidence       : "
                f"{observation['evidence']}"
            )

            print(
                f"Description    : "
                f"{observation['description']}"
            )

            print(
                f"Recommendation : "
                f"{observation['recommendation']}"
            )

    if robots_result["errors"]:

        print("\nrobots.txt Warnings:")

        for error in robots_result[
            "errors"
        ]:
            print(
                f"  - {error}"
            )
def print_sitemap_results(sitemap_result):
    """
    Display sitemap reconnaissance results.
    """

    print("\n[+] Sitemap Analysis\n")

    print(
        f"Status: {sitemap_result['status']}"
    )

    if sitemap_result["data"]:

        data = sitemap_result["data"]

        print(
            f"Exists     : "
            f"{'Yes' if data['exists'] else 'No'}"
        )

        print(
            f"Total URLs : "
            f"{data['total_urls']}"
        )

        if data["sitemaps"]:

            print("\nSitemaps:")

            for sitemap in data[
                "sitemaps"
            ]:

                print(
                    f"\n  URL    : "
                    f"{sitemap['requested_url']}"
                )

                print(
                    f"  Status : "
                    f"{sitemap['status']}"
                )

                if sitemap["type"]:
                    print(
                        f"  Type   : "
                        f"{sitemap['type']}"
                    )

        if data["urls"]:

            print("\nDiscovered URLs:")

            for url in data["urls"][:50]:
                print(
                    f"  {url}"
                )

            if len(data["urls"]) > 50:

                print(
                    f"\n  ... "
                    f"{len(data['urls']) - 50} "
                    f"additional URL(s) omitted "
                    f"from console output."
                )

    if sitemap_result["observations"]:

        print("\nSitemap Observations:")

        for observation in sitemap_result[
            "observations"
        ]:

            print(
                f"\n{observation['title']}"
            )

            print(
                f"Severity       : "
                f"{observation['severity']}"
            )

            print(
                f"Evidence       : "
                f"{observation['evidence']}"
            )

            print(
                f"Description    : "
                f"{observation['description']}"
            )

            print(
                f"Recommendation : "
                f"{observation['recommendation']}"
            )

    if sitemap_result["errors"]:

        print("\nSitemap Warnings:")

        for error in sitemap_result[
            "errors"
        ]:

            print(
                f"  - {error}"
            )

def main():
    """
    Main ReconForge execution controller.

    Workflow:
        1. Read target
        2. Validate target
        3. Run DNS reconnaissance
        4. Run HTTP reconnaissance
        5. Analyze security headers
        6. Display results
    """

    args = parse_arguments()

    logger.info("ReconForge started")

    logger.info(
        "Target received: %s",
        args.target
    )

    try:

        # -------------------------------------------------
        # STEP 1: Target validation
        # -------------------------------------------------

        target = normalize_target(
            args.target
        )
        print("\n[+] Pre-flight Target Check\n")

        preflight = check_target_availability(
            target
        )

        print(
            f"Target Status : {preflight['status']}"
        )

        print(
            f"Message       : {preflight['message']}"
        )


        if preflight["dns"]["addresses"]:

            print(
                "Resolved IPs  : "
                + ", ".join(
                    preflight["dns"]["addresses"]
                )
            )


        if not preflight["continue_recon"]:

            print(
                "\n[-] Reconnaissance stopped."
            )

            print(
                "Reason: Target is not currently "
                "available as a web target."
            )

            logger.warning(
                "Reconnaissance aborted during "
                "pre-flight check: %s",
                preflight["status"],
            )

            return 1


        print(
            "\n[+] Target available. "
            "Starting reconnaissance..."
        )
        logger.info(
            "Target normalized successfully: %s",
            target["hostname"]
        )

        print_target_information(
            target
        )
        # -------------------------------------------------
        # STEP 2: WHOIS reconnaissance
        # -------------------------------------------------

        whois_result = lookup_whois(
            target["hostname"]
        )

        print_whois_results(
            whois_result
        )


        # -------------------------------------------------
        # STEP 3: DNS reconnaissance
        # -------------------------------------------------

        dns_result = lookup_dns(
            target["hostname"]
        )

        print_dns_results(
            dns_result
        )
        # -------------------------------------------------
        # STEP 4: IP information
        # -------------------------------------------------

        ip_result = lookup_ip_information(
            dns_result
        )

        print_ip_results(
            ip_result
        )
        # -------------------------------------------------
        # STEP 5: HTTP reconnaissance
        # -------------------------------------------------

        http_result = fetch_http_information(
            target["https_url"]
        )

        print_http_results(
            http_result
        )
        # -------------------------------------------------
        # STEP 6:robots.txt reconnaissance
        # -------------------------------------------------

        robots_result = fetch_robots_txt(
            target["https_url"]
        )

        print_robots_results(
            robots_result
        )

        # -------------------------------------------------
        # STEP 7:Sitemap reconnaissance
        # -------------------------------------------------

        sitemap_result = fetch_sitemaps(
            target["https_url"],
            robots_result=robots_result,
        )

        print_sitemap_results(
            sitemap_result
        )

        # -------------------------------------------------
        # STEP 8: TLS certificate reconnaissance
        # -------------------------------------------------

        tls_result = inspect_tls_certificate(
            target["hostname"]
        )

        print_tls_results(
            tls_result
        )


        # -------------------------------------------------
        # STEP 9: Security header analysis
        # -------------------------------------------------

        security_result = analyze_security_headers(
            http_result
        )

        print_security_results(
            security_result
        )
        # -------------------------------------------------
        # STEP FINAL: Aggregate all scan results
        # -------------------------------------------------

        scan_result = build_scan_result(
            target=target,
            whois_result=whois_result,
            dns_result=dns_result,
            ip_result=ip_result,
            http_result=http_result,
            robots_result=robots_result,
            sitemap_result=sitemap_result,
            tls_result=tls_result,
            security_result=security_result,
        )
        from reporting.report_manager import generate_reports


        reports = generate_reports(
            scan_result,
            target["hostname"],
            formats="all",
        )
        print("\n[+] Reports Generated\n")

        if reports["json"]:
            print(f"JSON : {reports['json']}")

        if reports["html"]:
            print(f"HTML : {reports['html']}")

        if reports["pdf"]:
            print(f"PDF  : {reports['pdf']}")

    except TargetValidationError as error:

        logger.warning(
            "Target validation failed: %s",
            error
        )

        print(
            f"\n[-] Invalid target: {error}"
        )

        return 1

    except KeyboardInterrupt:

        logger.warning(
            "ReconForge interrupted by user"
        )

        print(
            "\n[-] ReconForge interrupted by user."
        )

        return 130

    except Exception:

        logger.exception(
            "Unexpected application error"
        )

        print(
            "\n[-] An unexpected error occurred. "
            "Check logs/reconforge.log for details."
        )

        return 1

    logger.info(
        "ReconForge execution completed"
    )

    return 0

def print_tls_results(tls_result):
    """
    Display TLS certificate reconnaissance results.
    """

    print("\n[+] TLS Certificate Analysis\n")

    print(
        f"Status            : "
        f"{tls_result['status']}"
    )

    if tls_result["data"]:

        data = tls_result["data"]

        print(
            f"Hostname          : "
            f"{data['hostname']}"
        )

        print(
            f"Port              : "
            f"{data['port']}"
        )

        print(
            f"TLS Version       : "
            f"{data['tls_version'] or 'Unknown'}"
        )

        print(
            f"Common Name       : "
            f"{data['common_name'] or 'Not available'}"
        )

        print(
            f"Serial Number     : "
            f"{data['serial_number'] or 'Not available'}"
        )

        print(
            f"Valid From        : "
            f"{data['valid_from'] or 'Unknown'}"
        )

        print(
            f"Valid Until       : "
            f"{data['valid_until'] or 'Unknown'}"
        )

        print(
            f"Days Remaining    : "
            f"{data['days_remaining']}"
        )

        print(
            f"Certificate Status: "
            f"{data['certificate_status']}"
        )

        print("\nIssuer:")

        if data["issuer"]:

            for name, value in data[
                "issuer"
            ].items():

                print(
                    f"  {name}: {value}"
                )

        else:
            print("  Not available")

        print("\nSubject:")

        if data["subject"]:

            for name, value in data[
                "subject"
            ].items():

                print(
                    f"  {name}: {value}"
                )

        else:
            print("  Not available")

        print("\nSubject Alternative Names:")

        if data["subject_alt_names"]:

            for san in data[
                "subject_alt_names"
            ]:

                print(
                    f"  {san}"
                )

        else:
            print("  No SAN entries found")

        cipher = data["cipher"]

        print("\nNegotiated Cipher:")

        print(
            f"  Name     : "
            f"{cipher['name'] or 'Unknown'}"
        )

        print(
            f"  Protocol : "
            f"{cipher['protocol'] or 'Unknown'}"
        )

        print(
            f"  Bits     : "
            f"{cipher['bits'] or 'Unknown'}"
        )

    if tls_result["observations"]:

        print("\nTLS Observations:")

        for observation in tls_result[
            "observations"
        ]:

            print(
                f"\n{observation['title']}"
            )

            print(
                f"Severity       : "
                f"{observation['severity']}"
            )

            print(
                f"Evidence       : "
                f"{observation['evidence']}"
            )

            print(
                f"Recommendation : "
                f"{observation['recommendation']}"
            )

    if tls_result["errors"]:

        print("\nTLS Warnings:")

        for error in tls_result["errors"]:
            print(
                f"  - {error}"
            )

if __name__ == "__main__":
    raise SystemExit(main())