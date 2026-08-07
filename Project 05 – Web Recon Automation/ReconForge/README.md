# ReconForge

### Automated Web Reconnaissance & Security Observation Framework

**Project 05 · Automation / Dev — Web Recon Automation Framework**

ReconForge is a modular Python-based web reconnaissance framework designed to automate the initial information-gathering phase of an **authorized web security assessment**.

Instead of manually checking multiple tools and services, ReconForge accepts a target domain or website URL and automatically collects publicly available reconnaissance information, performs basic security configuration analysis, and converts the collected information into structured professional reports.

The framework provides both a **Command-Line Interface (CLI)** and a lightweight **Flask web dashboard**.

> **Authorized Use Only:** ReconForge must only be used against domains and systems that you own or have explicit permission to assess.

---

## Features

ReconForge currently provides:

* Pre-flight target availability checking
* WHOIS information collection
* DNS record enumeration
* IP address discovery and classification
* Basic IP geolocation
* Reverse DNS lookup
* HTTP response inspection
* HTTP redirect analysis
* HTTP response header collection
* SSL/TLS certificate inspection
* TLS version and cipher information
* `robots.txt` discovery and parsing
* `sitemap.xml` discovery and parsing
* Security header analysis
* Server/application technology disclosure observations
* Cookie security observations
* Structured logging and error handling
* JSON evidence generation
* Professional HTML report generation
* PDF report export
* Command-line interface
* Local Flask dashboard

---

# Reconnaissance Workflow

ReconForge follows a structured reconnaissance pipeline:

```text
Target Domain / URL
        │
        ▼
Target Normalization
        │
        ▼
Pre-flight Availability Check
        │
        ├── DNS Resolution
        ├── HTTPS Availability
        └── HTTP Fallback
        │
        ▼
WHOIS Collection
        │
        ▼
DNS Enumeration
        │
        ▼
IP Analysis / Geolocation
        │
        ▼
HTTP Inspection
        │
        ├── Response Headers
        ├── Redirects
        └── Server Information
        │
        ▼
robots.txt Discovery
        │
        ▼
sitemap.xml Discovery
        │
        ▼
TLS Certificate Analysis
        │
        ▼
Security Header Analysis
        │
        ▼
Result Aggregation
        │
        ├── JSON Evidence
        ├── HTML Report
        └── PDF Report
```

---

# Core Reconnaissance Modules

## 1. Pre-flight Target Check

Before executing the complete reconnaissance workflow, ReconForge checks whether the supplied target is currently usable as a web target.

The pre-flight module performs:

* DNS resolution
* HTTPS availability testing
* HTTP fallback
* Target availability classification

Possible states include:

```text
ACTIVE
DNS_ONLY
UNRESOLVED
```

This prevents unnecessary reconnaissance operations against mistyped, unresolved, or currently unavailable web targets.

ReconForge does not rely solely on ICMP ping because many legitimate servers block ICMP traffic.

---

## 2. WHOIS Reconnaissance

The WHOIS module collects available domain registration information.

Collected information can include:

* Domain name
* Registrar
* WHOIS server
* Creation date
* Updated date
* Expiration date
* Domain age
* Name servers
* Domain status
* DNSSEC status
* Registrant organization
* Registrant country

WHOIS information may be incomplete or privacy-redacted depending on the registry and domain.

---

## 3. DNS Reconnaissance

ReconForge enumerates common DNS records using `dnspython`.

Supported record types include:

```text
A
AAAA
MX
NS
TXT
CNAME
SOA
```

These records can reveal information about:

* Hosting infrastructure
* Mail providers
* Name servers
* IPv4/IPv6 addresses
* Domain verification records
* Email security configuration
* DNS infrastructure

Missing DNS record types do not terminate the scan.

---

## 4. IP Address Analysis

IP addresses discovered through DNS are analyzed individually.

The module collects information such as:

* IP address
* IP version
* Public/private classification
* Reverse DNS hostname
* Country
* Region
* City
* Latitude/longitude when available
* ASN
* Network organization
* ISP/domain information when available

IP geolocation is approximate and should not be interpreted as the exact physical location of a server.

---

## 5. HTTP Reconnaissance

The HTTP module analyzes the target's web response.

Collected information includes:

* Requested URL
* Final URL
* HTTP status code
* Response reason
* Redirect count
* Redirect chain
* Response time
* Content type
* Content length
* Server header
* `X-Powered-By` header
* Complete HTTP response headers

This information provides an initial understanding of the target's web infrastructure and exposed technologies.

---

## 6. SSL/TLS Certificate Analysis

ReconForge inspects the TLS service exposed on port 443.

The module can collect:

* TLS version
* Certificate common name
* Subject
* Issuer
* Serial number
* Certificate validity start date
* Certificate expiration date
* Remaining validity period
* Subject Alternative Names (SANs)
* Negotiated cipher
* Cipher strength

Certificate information can help identify related hostnames and understand the target's HTTPS configuration.

---

## 7. robots.txt Analysis

ReconForge automatically attempts to retrieve:

```text
/robots.txt
```

When available, the module records:

* HTTP status
* Content
* User-Agent directives
* Allow directives
* Disallow directives
* Sitemap references
* Crawl-delay directives

The absence of `robots.txt` is treated as a normal condition rather than an application failure.

---

## 8. Sitemap Discovery

ReconForge attempts to discover and parse sitemap information from sources such as:

```text
/sitemap.xml
```

and sitemap references discovered inside `robots.txt`.

The module can process:

* Sitemap files
* URL sets
* Sitemap indexes
* Nested sitemap references

Sitemap discovery can provide useful information about publicly indexed application content.

---

# Security Observation Engine

ReconForge performs lightweight security configuration analysis against collected HTTP information.

It does **not** attempt exploitation.

The framework can identify observations involving headers such as:

* `Content-Security-Policy`
* `Strict-Transport-Security`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`
* `Cross-Origin-Opener-Policy`
* `Cross-Origin-Resource-Policy`

ReconForge can also identify information-disclosure observations such as:

* Server banner exposure
* `X-Powered-By` technology disclosure

Cookie-related security attributes may also be inspected when available.

Each observation can contain:

```text
Observation ID
Title
Severity
Evidence
Description
Recommendation
Source Module
```

Example:

```text
RF-001
Content-Security-Policy header not detected

Severity:
Medium

Evidence:
Missing HTTP response header: Content-Security-Policy

Recommendation:
Implement and test a restrictive Content-Security-Policy.
```

## Important Security Interpretation

A missing security header or exposed server banner is a **security observation**, not automatic proof of an exploitable vulnerability.

Manual validation and application context are required before an observation should be classified as a confirmed vulnerability.

---

# Architecture

ReconForge follows a modular architecture based on separation of responsibilities.

Each reconnaissance capability is implemented independently instead of placing all functionality inside one large Python script.

Example structure:

```text
ReconForge/
│
├── main.py
├── app.py
├── requirements.txt
├── README.md
│
├── core/
│   ├── target.py
│   ├── preflight.py
│   └── logger.py
│
├── modules/
│   ├── whois_lookup.py
│   ├── dns_lookup.py
│   ├── ip_lookup.py
│   ├── http_headers.py
│   ├── tls_certificate.py
│   ├── robots_fetcher.py
│   ├── sitemap_fetcher.py
│   └── security_headers.py
│
├── reporting/
│   ├── json_report.py
│   ├── html_report.py
│   ├── pdf_report.py
│   └── report_manager.py
│
├── templates/
│   ├── dashboard.html
│   └── report.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
│
├── samples/
│   ├── sample-recon-report.html
│   ├── sample-recon-report.pdf
│   └── sample-recon-evidence.json
│
├── reports/
└── logs/
```

## Why This Architecture?

Reconnaissance involves many independent network operations.

WHOIS may fail while DNS succeeds. A domain may resolve while its sitemap is unavailable. An external geolocation service may time out while HTTP and TLS analysis continue normally.

For this reason, ReconForge separates each responsibility into an independent module.

This provides:

* Better maintainability
* Reusable functions
* Easier debugging
* Failure isolation
* Cleaner reporting
* Easier future expansion
* Consistent structured results

Collection and presentation are also separated.

Reconnaissance modules collect information, the aggregation/reporting layer converts that information into a common scan structure, and different output components consume the same results.

```text
Recon Modules
      │
      ▼
Structured Results
      │
      ▼
Result Aggregation
      │
      ├──────────────┐
      ▼              ▼
     CLI          Dashboard
      │
      ▼
Reporting Layer
      │
 ┌────┼─────┐
 ▼    ▼     ▼
JSON HTML   PDF
```

---

# Failure Handling

Network reconnaissance is inherently unreliable.

ReconForge is designed so that an individual module failure does not unnecessarily terminate the entire scan.

Modules can return states such as:

```text
success
partial
failed
skipped
```

Examples of conditions handled by the framework include:

* DNS records not existing
* WHOIS fields being unavailable
* HTTP request timeout
* Connection failure
* `robots.txt` returning 404
* Sitemap not being available
* TLS connection failure
* Geolocation API failure
* Incomplete external data

Errors and warnings are recorded while the framework continues whenever possible.

---

# Logging

ReconForge maintains execution logs to assist with debugging and traceability.

Example events include:

```text
ReconForge started
Target received
Target normalized
Pre-flight completed
WHOIS lookup started
DNS records collected
HTTP reconnaissance completed
TLS analysis completed
Security observations generated
Reports generated
ReconForge execution completed
```

Logs are stored under the project's logging directory/configured log path.

---

# Installation

## Requirements

Recommended environment:

```text
Python 3.10+
Windows / Linux
Internet connection
```

For PDF generation, a supported local Chromium-based browser such as Microsoft Edge or Google Chrome may be required depending on the configured PDF exporter.

---

## Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
cd ReconForge
```

---

## Create a Virtual Environment

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

# Dependencies

Major dependencies used by ReconForge include:

| Dependency     | Purpose                                  |
| -------------- | ---------------------------------------- |
| Python         | Core framework                           |
| `requests`     | HTTP requests and web resource retrieval |
| `dnspython`    | DNS enumeration                          |
| `python-whois` | WHOIS information collection             |
| `Flask`        | Local web dashboard                      |
| `Jinja2`       | HTML report rendering                    |
| `ssl`          | TLS certificate inspection               |
| `socket`       | DNS/network operations                   |
| `ipaddress`    | IP classification                        |

An external IP information/geolocation service may be used for approximate public IP metadata.

PDF generation may use an installed Chromium-based browser to print the generated HTML report to PDF.

---

# CLI Usage

ReconForge accepts a target through the `--target` argument.

Example:

```bash
python main.py --target example.com
```

A complete URL can also be supplied:

```bash
python main.py --target https://example.com
```

ReconForge normalizes the supplied target before reconnaissance begins.

Example:

```text
Original Input : example.com
Hostname       : example.com
HTTPS URL      : https://example.com
HTTP URL       : http://example.com
```

The pre-flight module then determines whether reconnaissance should continue.

---

# Web Dashboard

ReconForge also provides a lightweight local Flask dashboard.

Start it with:

```bash
python app.py
```

The application will normally be available at:

```text
http://127.0.0.1:5000
```

The dashboard provides the workflow:

```text
Enter Authorized Target
        ↓
Check Target
        ↓
Pre-flight Status
        ↓
Start Recon
        ↓
Reconnaissance Modules
        ↓
Security Observations
        ↓
Report Generation
```

The dashboard displays:

* Target availability
* DNS status
* HTTP/HTTPS availability
* Module execution status
* Observation counts
* Severity summary
* Target information
* Security observations
* Report download options

---

# Report Generation

Console output alone is not used as the final deliverable.

ReconForge automatically converts collected reconnaissance data into structured report formats.

Supported outputs include:

## JSON Evidence

Contains structured raw reconnaissance results that can be processed programmatically.

Example:

```text
reports/example.com_TIMESTAMP_recon.json
```

## HTML Report

A formatted professional reconnaissance report intended for human review.

Example:

```text
reports/example.com_TIMESTAMP_report.html
```

## PDF Report

A portable version of the professional HTML report suitable for submission or sharing.

Example:

```text
reports/example.com_TIMESTAMP_report.pdf
```

---

# Report Contents

The professional report can include:

```text
Executive Summary

Target Information

Module Execution Summary

WHOIS Information

DNS Records

IP & Geolocation Information

HTTP Analysis

TLS Certificate Information

robots.txt Analysis

Sitemap Analysis

Security Observations

Severity Summary

Recommendations

Methodology

Limitations

Ethical Use Notice
```

The goal is to produce a report that can serve as initial reconnaissance documentation before an authorized penetration test.

---

# Sample Report

A sample reconnaissance report is included in the repository under:

```text
samples/
```

Example:

```text
samples/
├── sample-recon-report.html
├── sample-recon-report.pdf
└── sample-recon-evidence.json
```

The sample should only contain reconnaissance performed against a domain that the tester owns, controls, or is explicitly authorized to assess.

---

# Limitations

ReconForge intentionally has a limited scope.

Current limitations include:

* ReconForge performs reconnaissance, not exploitation.
* It does not perform credential attacks.
* It does not perform brute-force attacks.
* It does not attempt vulnerability exploitation.
* It does not perform unrestricted port scanning.
* WHOIS information may be privacy-redacted or incomplete.
* IP geolocation is approximate.
* External IP/geolocation services may be unavailable or rate-limited.
* CDN or WAF infrastructure may hide the origin server.
* DNS results depend on currently published records.
* Some websites may reject automated requests.
* `robots.txt` and sitemap information depends on publicly exposed resources.
* Missing security headers are observations rather than automatic proof of vulnerabilities.
* Security findings require manual validation.
* PDF generation may depend on a locally installed supported browser.

---

# Hardest Part of the Project

The hardest part of building ReconForge was not collecting individual pieces of reconnaissance information, but designing the framework so unreliable network operations did not break the complete scan.

WHOIS services can return incomplete information, DNS record types may not exist, websites may reject automated requests, TLS connections may fail, `robots.txt` or sitemap files may return 404 responses, and external IP/geolocation services can time out.

To handle this, the framework was designed around independent modules and structured result states rather than allowing individual exceptions to terminate the application.

A pre-flight target availability check was also introduced so obviously unresolved or unavailable targets can be identified before the complete reconnaissance process begins.

Another challenging part was normalizing results from different data sources into a structure that could be reused by the command-line interface, Flask dashboard, JSON evidence output, HTML report, and PDF report.

---

# What I Learned

Building ReconForge helped me understand that reconnaissance is much more than executing several security tools independently.

A useful reconnaissance framework needs to determine:

* What information should be collected
* Which sources should provide that information
* How different reconnaissance results relate to one another
* How network failures should be handled
* How collected evidence should be normalized
* How security observations should be interpreted
* How technical information should be presented professionally

Through this project, I gained practical understanding of:

* WHOIS registration information
* DNS record types
* IPv4 and IPv6 resolution
* Reverse DNS
* Public/private IP classification
* IP geolocation limitations
* HTTP response headers
* HTTP redirects
* Web server information disclosure
* TLS certificates
* Subject Alternative Names
* TLS versions and cipher suites
* `robots.txt`
* Sitemap structures
* Browser security headers
* Security configuration observations

I also learned an important reporting principle:

**An observation is not automatically a vulnerability.**

For example, a missing security header or exposed server banner provides useful security information, but its actual risk depends on application context and should be manually validated before being reported as a confirmed vulnerability.

From the software engineering side, this project improved my understanding of:

* Modular Python architecture
* Reusable functions
* Exception handling
* Structured logging
* Network programming
* API integration
* Structured data aggregation
* CLI development
* Flask development
* Jinja2 templating
* Automated reporting
* JSON evidence generation
* HTML report generation
* PDF export

---

# Future Improvements

Possible future improvements include:

* Asynchronous reconnaissance modules
* Configurable module selection
* Scan profiles
* Improved IPv6 support
* Additional certificate analysis
* DNSSEC analysis
* Email security observations for SPF, DKIM, and DMARC
* Historical scan comparison
* Report severity filtering
* Export to additional formats
* Automated unit and integration tests
* Docker packaging
* Optional authenticated dashboard
* Multi-target authorized assessment support

These features are intentionally outside the current internship project scope.

---

# Ethical Usage

Reconnaissance can reveal sensitive information about internet-facing infrastructure.

ReconForge is intended for:

* Personal lab environments
* Domains you own
* Systems you control
* Security training environments
* Explicitly authorized penetration testing engagements

Do **not** use ReconForge against systems without permission.

The user is responsible for ensuring that all reconnaissance activities comply with applicable laws, organizational policies, contracts, and authorization boundaries.

---

# Project Objective

This project was developed as part of:

**Project 05 · Automation / Dev**

### Web Recon Automation Framework

The objective was to engineer a reusable reconnaissance framework rather than manually executing multiple independent tools.

The project demonstrates:

* Reconnaissance methodology
* Python automation
* Network programming
* Modular software design
* Error handling
* Security configuration analysis
* Professional security reporting

---

## Disclaimer

ReconForge is an educational and authorized security-assessment tool.

It is not intended for unauthorized scanning, exploitation, disruption, or access to systems without permission.

---

**ReconForge — automate the collection, preserve the evidence, understand the target.**
