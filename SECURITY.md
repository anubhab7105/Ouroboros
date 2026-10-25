# Security Policy

## Supported versions

MULEGUARD is an academic and demonstration prototype, not a production financial system. Security fixes are considered for the current default branch. Releases or other branches may not receive backports.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues, pull requests, discussions, or social media.

Use GitHub's **Report a vulnerability** feature on this repository's **Security** tab when private vulnerability reporting is enabled. If that option is unavailable, contact the repository maintainer through their GitHub profile and ask for a private channel. Do not send real customer data, credentials, access tokens, or production secrets.

A useful report includes:
- A short description and affected component or commit.
- Reproduction steps using a local environment and synthetic data.
- The security impact and realistic attack prerequisites.
- Relevant logs or screenshots after removing secrets and personal data.
- A suggested mitigation, if known.

Please allow the maintainer reasonable time to investigate and prepare a fix before publishing details. We will acknowledge reports, validate the issue, and coordinate a fix and disclosure where possible; response times are not guaranteed.

## Scope and safety

MULEGUARD is synthetic-first. Do not test against real banking systems, real customer accounts, third-party services, or infrastructure you do not own or have explicit permission to test. Never include real financial or personal data in a report.

The application is not designed or approved for production banking, regulated financial-crime workflows, or automated adverse customer actions. Findings about prototype limitations are welcome, but please distinguish them from exploitable vulnerabilities.
