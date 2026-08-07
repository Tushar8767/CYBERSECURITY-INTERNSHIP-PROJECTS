from datetime import datetime

from core.logger import setup_logger

from reporting.json_report import save_json_report
from reporting.html_report import generate_html_report
from reporting.pdf_report import generate_pdf_report


logger = setup_logger(
    "reconforge.reporting"
)


def generate_reports(
    scan_result,
    hostname,
    formats=None,
):
    """
    Generate requested ReconForge report formats.

    Supported:
        json
        html
        pdf
        all

    PDF automatically requires HTML because
    the HTML report is used as its source.
    """

    if formats is None:
        formats = {
            "json",
            "html",
            "pdf",
        }

    if isinstance(formats, str):

        if formats == "all":

            formats = {
                "json",
                "html",
                "pdf",
            }

        else:

            formats = {
                formats
            }

    formats = set(
        formats
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    paths = {
        "json": None,
        "html": None,
        "pdf": None,
    }

    # JSON

    if "json" in formats:

        paths["json"] = save_json_report(
            scan_result,
            hostname,
        )

    # HTML is required directly or by PDF.

    if (
        "html" in formats
        or "pdf" in formats
    ):

        paths["html"] = generate_html_report(
            scan_result,
            hostname,
            timestamp=timestamp,
        )

    # PDF

    if "pdf" in formats:

        try:

            paths["pdf"] = generate_pdf_report(
                paths["html"]
            )

        except Exception as error:

            logger.warning(
                "PDF generation unavailable: %s",
                error,
            )

    return {
        key: (
            str(value)
            if value
            else None
        )
        for key, value
        in paths.items()
    }