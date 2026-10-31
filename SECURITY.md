# Security Policy

## Authorized use

SENTINEL APEX is intended for defensive monitoring of systems that the operator owns or is explicitly authorized to assess. Do not use the project to inspect, scan, or interfere with third-party systems without permission.

## Reporting a vulnerability

Please do not publish exploitable details, credentials, tokens, customer data, or sensitive logs in a public issue.

Use GitHub Private Vulnerability Reporting when available. Otherwise, contact the maintainers through the team contact information in the repository README and include:

- the affected component and version or commit;
- clear reproduction steps using non-sensitive test data;
- the expected and observed behavior;
- the likely impact;
- a suggested mitigation, if known.

We will acknowledge a report, assess its severity, coordinate a fix, and credit the reporter when requested and appropriate.

## Secrets and evidence

Never commit `.env` files, private keys, service-account files, API tokens, production captures, or unredacted incident evidence. Use placeholders in examples and remove sensitive values from screenshots and logs.
