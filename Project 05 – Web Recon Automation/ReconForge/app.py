from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
)

from core.target import (
    normalize_target,
    TargetValidationError,
)

from core.preflight import (
    check_target_availability,
)

from core.logger import setup_logger

from modules.whois_lookup import lookup_whois
from modules.dns_lookup import lookup_dns
from modules.ip_lookup import lookup_ip_information
from modules.http_headers import fetch_http_information
from modules.robots_fetcher import fetch_robots_txt
from modules.sitemap_fetcher import fetch_sitemaps
from modules.tls_certificate import inspect_tls_certificate
from modules.security_headers import analyze_security_headers

from reporting.json_report import build_scan_result
from reporting.report_manager import generate_reports


app = Flask(__name__)

logger = setup_logger(
    "reconforge.dashboard"
)


REPORT_DIR = Path(
    "reports"
).resolve()


# Stores the most recent dashboard report paths.
# Fine for this local internship dashboard.
latest_reports = {
    "json": None,
    "html": None,
    "pdf": None,
}


@app.route("/")
def dashboard():
    """
    Render ReconForge dashboard.
    """

    return render_template(
        "dashboard.html"
    )


@app.route(
    "/api/preflight",
    methods=["POST"]
)
def preflight():
    """
    Check target availability before running
    full reconnaissance.
    """

    payload = request.get_json(
        silent=True
    ) or {}

    raw_target = payload.get(
        "target",
        ""
    ).strip()

    if not raw_target:

        return jsonify({
            "success": False,
            "error": "Target is required.",
        }), 400

    try:

        target = normalize_target(
            raw_target
        )

        result = check_target_availability(
            target
        )

        return jsonify({
            "success": True,
            "target": target,
            "preflight": result,
        })

    except TargetValidationError as error:

        return jsonify({
            "success": False,
            "error": str(error),
        }), 400

    except Exception:

        logger.exception(
            "Pre-flight check failed"
        )

        return jsonify({
            "success": False,
            "error": (
                "Unable to complete "
                "target availability check."
            ),
        }), 500


@app.route(
    "/api/scan",
    methods=["POST"]
)
def run_scan():
    """
    Perform complete ReconForge scan.
    """

    payload = request.get_json(
        silent=True
    ) or {}

    raw_target = payload.get(
        "target",
        ""
    ).strip()

    if not raw_target:

        return jsonify({
            "success": False,
            "error": "Target is required.",
        }), 400

    logger.info(
        "Dashboard scan requested: %s",
        raw_target,
    )

    try:

        # ---------------------------------------------
        # TARGET
        # ---------------------------------------------

        target = normalize_target(
            raw_target
        )

        # ---------------------------------------------
        # PREFLIGHT
        # ---------------------------------------------

        availability = (
            check_target_availability(
                target
            )
        )

        if not availability[
            "continue_recon"
        ]:

            return jsonify({
                "success": False,
                "preflight_failed": True,
                "preflight": availability,
                "error": availability[
                    "message"
                ],
            }), 400

        # ---------------------------------------------
        # WHOIS
        # ---------------------------------------------

        whois_result = lookup_whois(
            target["hostname"]
        )

        # ---------------------------------------------
        # DNS
        # ---------------------------------------------

        dns_result = lookup_dns(
            target["hostname"]
        )

        # ---------------------------------------------
        # IP
        # ---------------------------------------------

        ip_result = lookup_ip_information(
            dns_result
        )

        # ---------------------------------------------
        # HTTP
        # ---------------------------------------------

        preferred_url = (
            availability.get(
                "preferred_url"
            )
            or target["https_url"]
        )

        http_result = (
            fetch_http_information(
                preferred_url
            )
        )

        # ---------------------------------------------
        # ROBOTS
        # ---------------------------------------------

        robots_result = fetch_robots_txt(
            preferred_url
        )

        # ---------------------------------------------
        # SITEMAP
        # ---------------------------------------------

        sitemap_result = fetch_sitemaps(
            preferred_url,
            robots_result=robots_result,
        )

        # ---------------------------------------------
        # TLS
        # ---------------------------------------------

        tls_result = inspect_tls_certificate(
            target["hostname"]
        )

        # ---------------------------------------------
        # SECURITY HEADERS
        # ---------------------------------------------

        security_result = (
            analyze_security_headers(
                http_result
            )
        )

        # ---------------------------------------------
        # AGGREGATE
        # ---------------------------------------------

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

        # ---------------------------------------------
        # REPORTS
        # ---------------------------------------------

        reports = generate_reports(
            scan_result,
            target["hostname"],
            formats="all",
        )

        latest_reports.update(
            reports
        )

        logger.info(
            "Dashboard scan completed for %s",
            target["hostname"],
        )

        return jsonify({
            "success": True,

            "target": target,

            "preflight": availability,

            "scan": scan_result[
                "scan"
            ],

            "observations": scan_result[
                "observations"
            ],

            "modules": scan_result[
                "modules"
            ],

            "reports": {
                "json": (
                    "/reports/json"
                    if reports.get("json")
                    else None
                ),

                "html": (
                    "/reports/html"
                    if reports.get("html")
                    else None
                ),

                "pdf": (
                    "/reports/pdf"
                    if reports.get("pdf")
                    else None
                ),
            },
        })

    except TargetValidationError as error:

        return jsonify({
            "success": False,
            "error": str(error),
        }), 400

    except Exception:

        logger.exception(
            "Dashboard reconnaissance failed"
        )

        return jsonify({
            "success": False,
            "error": (
                "Reconnaissance failed. "
                "Check ReconForge logs."
            ),
        }), 500


def _send_report(
    report_type,
    download=False,
):
    """
    Safely return generated report file.
    """

    path_value = latest_reports.get(
        report_type
    )

    if not path_value:

        return (
            "Report has not been generated.",
            404
        )

    path = Path(
        path_value
    ).resolve()

    if (
        not path.exists()
        or REPORT_DIR not in path.parents
    ):

        return (
            "Report unavailable.",
            404
        )

    return send_file(
        path,
        as_attachment=download,
        download_name=path.name,
    )


@app.route("/reports/html")
def view_html_report():
    """
    Open latest HTML report in browser.
    """

    return _send_report(
        "html",
        download=False,
    )


@app.route("/reports/pdf")
def download_pdf_report():
    """
    Download latest PDF report.
    """

    return _send_report(
        "pdf",
        download=True,
    )


@app.route("/reports/json")
def download_json_report():
    """
    Download latest raw JSON evidence.
    """

    return _send_report(
        "json",
        download=True,
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )