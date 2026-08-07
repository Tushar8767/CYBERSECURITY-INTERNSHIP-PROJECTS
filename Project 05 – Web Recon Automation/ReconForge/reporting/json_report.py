import json
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIR = Path("reports")


def _safe_module_result(result, module_name):
    """
    Normalize a module result.

    Task:
    - Ensure every module has the expected keys
    - Prevent missing fields from breaking report generation
    """

    if not isinstance(result, dict):
        return {
            "module": module_name,
            "status": "failed",
            "data": {},
            "observations": [],
            "errors": [
                "Module returned an invalid result structure."
            ],
        }

    return {
        "module": result.get(
            "module",
            module_name
        ),
        "status": result.get(
            "status",
            "unknown"
        ),
        "data": result.get(
            "data",
            {}
        ),
        "observations": result.get(
            "observations",
            []
        ),
        "errors": result.get(
            "errors",
            []
        ),
    }


def _collect_observations(modules):
    """
    Collect observations from every module.

    Task:
    - Combine findings from security headers, TLS,
      robots.txt, sitemap, etc.
    - Assign central RF-001 style IDs
    - Avoid duplicate local IDs
    """

    collected = []

    counter = 1

    for module_name, module_result in modules.items():

        observations = module_result.get(
            "observations",
            []
        )

        for observation in observations:

            normalized = dict(
                observation
            )

            normalized["id"] = (
                f"RF-{counter:03}"
            )

            normalized["source_module"] = (
                module_name
            )

            collected.append(
                normalized
            )

            counter += 1

    return collected


def _calculate_severity_summary(observations):
    """
    Count observations by severity.

    Task:
    - Produce totals for High, Medium, Low,
      Informational
    """

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for observation in observations:

        severity = observation.get(
            "severity",
            "Informational"
        )

        if severity not in summary:
            severity = "Informational"

        summary[severity] += 1

    return summary


def _calculate_module_summary(modules):
    """
    Count module execution statuses.

    Task:
    - Determine how many modules succeeded
    - Count partial, failed, and skipped modules
    """

    summary = {
        "total": len(modules),
        "success": 0,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
        "unknown": 0,
    }

    for result in modules.values():

        status = result.get(
            "status",
            "unknown"
        )

        if status in summary:
            summary[status] += 1

        else:
            summary["unknown"] += 1

    return summary


def build_scan_result(
    target,
    whois_result,
    dns_result,
    ip_result,
    http_result,
    robots_result,
    sitemap_result,
    tls_result,
    security_result,
):
    """
    Build the complete ReconForge scan record.

    Task:
    - Combine all module outputs
    - Add metadata
    - Aggregate observations
    - Calculate severity/module summaries
    """

    modules = {
        "whois": _safe_module_result(
            whois_result,
            "whois_lookup",
        ),

        "dns": _safe_module_result(
            dns_result,
            "dns_lookup",
        ),

        "ip": _safe_module_result(
            ip_result,
            "ip_lookup",
        ),

        "http": _safe_module_result(
            http_result,
            "http_headers",
        ),

        "robots": _safe_module_result(
            robots_result,
            "robots_fetcher",
        ),

        "sitemap": _safe_module_result(
            sitemap_result,
            "sitemap_fetcher",
        ),

        "tls": _safe_module_result(
            tls_result,
            "tls_certificate",
        ),

        "security_headers": _safe_module_result(
            security_result,
            "security_headers",
        ),
    }

    observations = _collect_observations(
        modules
    )

    severity_summary = (
        _calculate_severity_summary(
            observations
        )
    )

    module_summary = (
        _calculate_module_summary(
            modules
        )
    )

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "tool": {
            "name": "ReconForge",
            "version": "1.0.0",
            "description": (
                "Authorized Web Reconnaissance Framework"
            ),
        },

        "scan": {
            "generated_at": generated_at,
            "target": target,
            "module_summary": module_summary,
            "total_observations": len(
                observations
            ),
            "severity_summary": severity_summary,
        },

        "observations": observations,

        "modules": modules,

        "limitations": [
            (
                "ReconForge performs reconnaissance and "
                "configuration observations only."
            ),
            (
                "Results should be manually validated before "
                "being treated as confirmed vulnerabilities."
            ),
            (
                "IP geolocation represents approximate network "
                "location and not a precise physical location."
            ),
            (
                "WHOIS information may be incomplete or redacted "
                "by domain registries."
            ),
        ],
    }


def save_json_report(
    scan_result,
    hostname,
    output_path=None,
):
    """
    Save aggregated reconnaissance results as JSON.

    Task:
    - Create reports directory
    - Generate a safe filename
    - Write structured JSON evidence
    """

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_hostname = (
        hostname
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )

    if output_path:
        path = Path(
            output_path
        )

    else:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        path = REPORT_DIR / (
            f"{safe_hostname}_"
            f"{timestamp}_recon.json"
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            scan_result,
            file,
            indent=4,
            ensure_ascii=False,
            default=str,
        )

    return path