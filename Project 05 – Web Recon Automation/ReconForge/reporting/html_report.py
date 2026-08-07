from datetime import datetime
from pathlib import Path

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from core.logger import setup_logger


logger = setup_logger("reconforge.html_report")


REPORT_DIR = Path("reports")

TEMPLATE_DIR = Path("templates")


def _create_environment():
    """
    Create the Jinja2 template environment.

    Task:
    - Load templates from /templates
    - Enable HTML escaping
    - Prepare report rendering engine
    """

    return Environment(
        loader=FileSystemLoader(
            str(TEMPLATE_DIR)
        ),
        autoescape=select_autoescape(
            ["html", "xml"]
        ),
    )


def _safe_filename(hostname):
    """
    Convert hostname into a safe filename.
    """

    return (
        hostname
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .strip()
    )


def _generate_timestamp():
    """
    Generate one timestamp for report filenames.
    """

    return datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


def generate_html_report(
    scan_result,
    hostname,
    output_path=None,
    timestamp=None,
):
    """
    Generate the professional ReconForge HTML report.

    Task:
    - Load report.html
    - Pass aggregated scan data to template
    - Generate standalone HTML file
    """

    logger.info(
        "Starting HTML report generation for %s",
        hostname,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_hostname = _safe_filename(
        hostname
    )

    if timestamp is None:
        timestamp = _generate_timestamp()

    if output_path:

        path = Path(
            output_path
        )

    else:

        path = REPORT_DIR / (
            f"{safe_hostname}_"
            f"{timestamp}_report.html"
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = _create_environment()

    template = environment.get_template(
        "report.html"
    )

    html = template.render(
        report=scan_result,
        scan=scan_result.get(
            "scan",
            {}
        ),
        target=scan_result.get(
            "scan",
            {}
        ).get(
            "target",
            {}
        ),
        modules=scan_result.get(
            "modules",
            {}
        ),
        observations=scan_result.get(
            "observations",
            []
        ),
        limitations=scan_result.get(
            "limitations",
            []
        ),
    )

    path.write_text(
        html,
        encoding="utf-8",
    )

    logger.info(
        "HTML report generated: %s",
        path,
    )

    return path