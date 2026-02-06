# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of `LatticeGuard` seriously. If you have found a vulnerability, please do not open an issue on GitHub. Instead, please report it via email.

### How to Report

Please email us at **waqasobeidy@gmail.com** with the subject line `[SECURITY] Vulnerability Report`.

Include as much information as possible:
*   Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
*   Full paths of source file(s) related to the manifestation of the issue
*   The location of the affected source code (tag/branch/commit or direct URL)
*   Any special configuration required to reproduce the issue
*   Step-by-step instructions to reproduce the issue
*   Proof-of-concept or exploit code (if existing)
*   Impact of the issue, including how an attacker might exploit the issue

We will acknowledge your report within 48 hours and provide an estimated timeframe for a fix.

## Security Features

LatticeGuard allows running arbitrary code analysis. To ensure the security of the scanner itself:
1.  **Input Validation**: Remote URLs are validated. Local file scanning is disabled by default (see `ALLOW_LOCAL_SCAN`).
2.  **Isolation**: We recommend running scanners in ephemeral Docker containers (as provided by the `docker-compose.yaml`).
3.  **Dependencies**: We regularly scan our own dependencies for vulnerabilities.
