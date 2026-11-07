# Security policy

## Supported versions

Only the latest release gets fixes. Kanareika is pre-1.0: upgrade to the newest `v0.x.y` before reporting.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via
[GitHub private vulnerability reporting](https://github.com/mikekosulin/kanareika/security/advisories/new)
(Security tab → *Report a vulnerability*).

Include what you need to reproduce it: version (`kanareika --version`), OS, the command or org file (with your
addresses and names removed), and what an attacker gains.

What to expect:

- an acknowledgement within 3 business days;
- an assessment and a fix plan within 14 days;
- a fixed release and a GitHub Security Advisory crediting you (unless you prefer otherwise).

## Scope

In scope — anything where Kanareika itself weakens the hosts it audits or the machine it runs on, for example:

- a scan that changes state on a host (it must stay read-only), or runs commands beyond what the docs describe;
- SSH host key checking bypassed, credentials or keys leaked into reports, logs or the dashboard;
- the dashboard or the MCP server reachable beyond localhost without `--token`, or exploitable from a page in the
  browser (for example starting a scan from another site: scans need the page's CSRF token, and on localhost only
  requests addressed to a loopback name are answered);
- data from one organization showing up in another's reports;
- a malicious host or container image making Kanareika execute code on the auditor's machine.

Out of scope: vulnerabilities Kanareika *finds* on your servers (that is its job), issues in third-party tools it
calls (report those upstream: trivy, OpenSSH, …), and findings that need an already compromised auditor machine.

## Verifying releases

Every release binary has a build provenance attestation and is listed in `SHA256SUMS`:

```bash
gh attestation verify kanareika-linux-amd64 --repo mikekosulin/kanareika
sha256sum -c SHA256SUMS --ignore-missing
```
