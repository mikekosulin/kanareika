# Kanareika

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**English** · [Русский](README.ru.md)

Agentless, read-only security audit of your servers over SSH: what to patch first, who can get in, what is exposed,
whether the host is healthy — with rollback-ready fix steps. One binary, one YAML per organization, data stays local.

![Dashboard (demo data)](docs/dashboard.png)

```bash
# download kanareika-<os>-<arch> from the release (or: make bin -> dist/kanareika); nothing else to install
kanareika init                   # orgs/, secrets/, reports/ in the current directory (or --home DIR)
kanareika org new myorg          # describe hosts, jump hosts and consent in orgs/myorg.yml
kanareika validate myorg
kanareika db update              # vulnerability DBs and feeds (isolated network: db export / db import)
kanareika scan myorg
kanareika                        # terminal interface (TUI): findings, hosts, runs, scans
kanareika web                    # web interface at http://127.0.0.1:8088; scans can be started there too
```

Three interfaces over the same data and rules: the TUI (`kanareika`, k9s-style; `?` shows the keys, `o` sets up the panels, kept in
`~/.config/kanareika/tui.json` or the OS equivalent), the web
(`kanareika web`) and commands for scripts and cron (`kanareika --help`). The TUI can also attach to a remote
`kanareika web`: `kanareika tui --url http://host:8088 --token …`.

- **Vulnerabilities** — OS packages, images, jars/lockfiles via trivy built into the binary (only its DBs are downloaded, or imported offline); backports and fix
  availability verified on the host; **P1–P4** by KEV, EPSS, exposure and pre-auth RCE.
- **Access & exposure** — SSH password login per user, keys, logins and attackers, open ports, firewalls, external scan.
- **Health** — kernel errors, disks, memory, time sync, pending reboots.
- **Fixing** — pick actions → a ready task for an engineer or AI agent (apply / verify / rollback); MCP for agents.
- **Safe by design** — read-only, per-org isolation, changed host keys refused, consent required, web interface on localhost only.

Details: [docs/org-file.md](docs/org-file.md) · `kanareika --help`

License: [MIT](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)
