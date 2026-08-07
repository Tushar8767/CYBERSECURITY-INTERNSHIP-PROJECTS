import shutil
import subprocess
from pathlib import Path

from core.logger import setup_logger


logger = setup_logger(
    "reconforge.pdf_report"
)


BROWSER_PATHS = [
    # Microsoft Edge
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",

    # Google Chrome
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def _find_browser():
    """
    Locate a Chromium-based browser.

    Task:
    - Check PATH first
    - Check common Windows installation locations
    - Prefer Edge/Chrome already installed on the system
    """

    commands = [
        "msedge",
        "chrome",
        "google-chrome",
        "chromium",
    ]

    for command in commands:

        path = shutil.which(
            command
        )

        if path:
            return Path(path)

    for browser_path in BROWSER_PATHS:

        path = Path(
            browser_path
        )

        if path.exists():
            return path

    return None


def generate_pdf_report(
    html_path,
    pdf_path=None,
):
    """
    Convert ReconForge HTML report to PDF
    using a local Chromium-based browser.

    Task:
    - Find Edge or Chrome
    - Open HTML in headless mode
    - Print page to PDF
    - Return generated PDF path
    """

    html_path = Path(
        html_path
    ).resolve()

    if not html_path.exists():

        raise FileNotFoundError(
            f"HTML report not found: "
            f"{html_path}"
        )

    if pdf_path is None:

        pdf_path = (
            html_path.parent
            / f"{html_path.stem}.pdf"
        )

    else:

        pdf_path = Path(
            pdf_path
        ).resolve()

    browser = _find_browser()

    if browser is None:

        raise RuntimeError(
            "Microsoft Edge or Google Chrome "
            "could not be located."
        )

    logger.info(
        "Using browser for PDF export: %s",
        browser,
    )

    file_url = html_path.as_uri()

    command = [
        str(browser),

        "--headless",

        "--disable-gpu",

        "--no-pdf-header-footer",

        f"--print-to-pdf={pdf_path}",

        file_url,
    ]

    logger.info(
        "Generating PDF report from %s",
        html_path,
    )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    except subprocess.TimeoutExpired as error:

        raise RuntimeError(
            "PDF generation timed out."
        ) from error

    if result.returncode != 0:

        raise RuntimeError(
            "Browser PDF generation failed. "
            f"{result.stderr.strip()}"
        )

    if not pdf_path.exists():

        raise RuntimeError(
            "Browser completed but PDF file "
            "was not created."
        )

    logger.info(
        "PDF report generated: %s",
        pdf_path,
    )

    return pdf_path