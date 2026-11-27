# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/templatecage/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| 1.x | Supported |

Security fixes are applied to the latest release line.

## Scope

This policy covers server-side template injection auditing and the bounded data-only template renderer.

In scope:

- A concrete SSTI detection bypass in a scanned delimiter family.
- Renderer access to inherited, getter, function, proxy or prototype-chain values.
- Output escaping, compiled-template integrity, iteration, nesting or output bound bypasses.
- CLI decoding or terminal neutralization failures with security impact.

Out of scope:

- Vulnerabilities in a third-party template engine not caused by this library.
- Applications that evaluate rendered output again as a template.
- Static markup intentionally supplied by a trusted application.

## Coordinated disclosure

- Acknowledgment: within 48 hours.
- Initial assessment: within 7 calendar days.
- Fix or mitigation plan: within 30 calendar days for confirmed high-impact reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
