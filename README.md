# Kanareika

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**English** · [Русский](README.ru.md)

Agentless, read-only security audit of your servers over SSH: what to patch first, who can get in, what is exposed,
whether the host is healthy — with rollback-ready fix steps. One binary, one YAML per organization, data stays local.

![Dashboard (demo data)](docs/dashboard.png)

```bash
make bin                     # or download kanareika-<os>-<arch> from the release
make new-org ORG=myorg       # describe hosts, jump hosts and consent in orgs/myorg.yml
make feeds && make scan ORG=myorg
make dashboard               # http://127.0.0.1:8088
```

- **Vulnerabilities** — OS packages, images, jars/lockfiles via trivy built into the binary (only its DBs are downloaded, or imported offline); backports and fix
  availability verified on the host; **P1–P4** by KEV, EPSS, exposure and pre-auth RCE.
- **Access & exposure** — SSH password login per user, keys, logins and attackers, open ports, firewalls, external scan.
- **Health** — kernel errors, disks, memory, time sync, pending reboots.
- **Fixing** — pick actions → a ready task for an engineer or AI agent (apply / verify / rollback); MCP for agents.
- **Safe by design** — read-only, per-org isolation, changed host keys refused, consent required, localhost dashboard.

Details: [docs/org-file.md](docs/org-file.md) · `kanareika --help`

License: [MIT](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)
