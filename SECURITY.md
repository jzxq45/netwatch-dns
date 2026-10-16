# Security policy

## Reporting a vulnerability

netwatch-dns is a self-hosted, single-admin tool. If you found a
vulnerability, please report it privately:

- Email: `security@yourdomain.invalid` *(replace with real address before publishing)*
- Или через GitHub: open a private security advisory (Security → Advisories).

Please include: affected version (commit hash), setup details (what listens
on what), reproduction steps. Do not open public issues for exploitable bugs.

## Supported versions
Only the latest `main` is supported.

## Threat model notes
- The web UI binds to `127.0.0.1:8080` by default; expose to LAN consciously
  (`web_listen: 0.0.0.0:8080`) and consider `web_token` authentication.
- The DNS server binds to `0.0.0.0:53`; it is meant for your LAN only.
  Do not port-forward 53 from the internet (DNS amplification abuse).
- Logs (dns_log, devices) are personal data in the legal sense: they stay on
  your disk, there is no telemetry of any kind — no analytics, no phone-home.