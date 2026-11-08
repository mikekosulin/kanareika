<h1><img src="docs/brand/banner-en.png" alt="Kanareika: security audit of your servers over SSH"></h1>

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mikekosulin/kanareika/badges/coverage.json)](https://github.com/mikekosulin/kanareika/actions/workflows/coverage.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Stars](https://img.shields.io/github/stars/mikekosulin/kanareika?style=social)](https://github.com/mikekosulin/kanareika)

**English** · [Español](docs/readme/README.es.md) · [Français](docs/readme/README.fr.md) · [Português](docs/readme/README.pt.md) · [Русский](docs/readme/README.ru.md) · [中文](docs/readme/README.zh.md) · [日本語](docs/readme/README.ja.md) · [한국어](docs/readme/README.ko.md)

Agentless, read-only security audit of your servers over SSH: what to patch first, who can get in, what is exposed, whether the hosts are healthy — with fix steps that can be rolled back. One binary, one YAML per organization; the data stays on your machine.

### Terminal interface

Run `kanareika`. It opens on ToDo: what to fix first, most urgent at the top.

![Demo data, made up.](docs/screenshots/tui-en.png)

### Web interface

Run `kanareika web` for the same data in a browser, with the trend of the last 30 runs.

![Demo data, made up.](docs/screenshots/web-en.png)

<sub>Demo data, made up.</sub>

### Install

Homebrew (macOS, Linux):

```bash
brew install mikekosulin/tap/kanareika
```

Linux without Homebrew: downloads the binary for your architecture (amd64 or arm64), checks it against the release checksums and installs it to `/usr/local/bin`:

```bash
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSLO "https://github.com/mikekosulin/kanareika/releases/latest/download/kanareika-linux-$arch"
curl -fsSL https://github.com/mikekosulin/kanareika/releases/latest/download/SHA256SUMS | sha256sum -c --ignore-missing
sudo install -m 755 "kanareika-linux-$arch" /usr/local/bin/kanareika
```

Windows (PowerShell):

```powershell
Invoke-WebRequest https://github.com/mikekosulin/kanareika/releases/latest/download/kanareika-windows-amd64.exe -OutFile kanareika.exe
```

On ARM, download `kanareika-windows-arm64.exe` instead. All binaries are on the [latest release](https://github.com/mikekosulin/kanareika/releases/latest) page.

### Quick start

1. Create the working directory: `orgs/`, `secrets/` and `reports/` appear in the current directory (or in another one, with `--home DIR`).

   ```bash
   kanareika init
   ```

2. Add an organization, then describe its hosts, jump hosts and consent to scan in `orgs/myorg.yml`.

   ```bash
   kanareika org new myorg
   ```

3. Check the file.

   ```bash
   kanareika validate myorg
   ```

4. Download the vulnerability databases. On an isolated network, carry them over with `db export` and `db import`.

   ```bash
   kanareika db update
   ```

5. Run the scan.

   ```bash
   kanareika scan myorg
   ```

6. Open the results in the terminal interface:

   ```bash
   kanareika
   ```

   or in the web interface, at http://127.0.0.1:8088 (it listens on localhost only):

   ```bash
   kanareika web
   ```

   Another port: `--port 9000`; `--port 0` takes any free one.

**Four ways in, same data and rules:**

- **TUI**, the main one — `kanareika`: `?` for keys, `o` for panels, `L` for language. Attaches to a remote web too: `kanareika tui --url http://host:8088 --token …`.
- **Web** — `kanareika web`: dashboards, trends, host details; scans start from the page.
- **Commands** — for scripts and cron: `kanareika --help`.
- **MCP** — `kanareika mcp`: read-only tools for AI agents (Claude Code and others).

**What it checks:**

- **Vulnerabilities** — OS packages, images, jars and lockfiles via trivy built into the binary; backports and fix availability verified on the host; **P1–P4** by KEV, EPSS, exposure and pre-auth RCE.
- **Access and exposure** — SSH password logins, keys, logins and attackers, open ports, firewalls, external scan.
- **Health** — kernel errors, disks, memory, time sync, pending reboots.
- **Fixing** — selected actions become a ready task for an engineer or an AI agent: apply, verify, roll back.
- **Safe by design** — read-only, organizations isolated, changed host keys refused, no scan without consent, the web interface on localhost only (or with a token).

**Disclaimer.** Kanareika reports what it finds; it does not promise to find everything. Priorities and fix steps are advice: review them before running anything on your hosts. Audit only servers you are allowed to. Provided as is, without warranty ([MIT](LICENSE)).

Like it? [Star it](https://github.com/mikekosulin/kanareika) · Something wrong? [Open an issue](https://github.com/mikekosulin/kanareika/issues/new/choose) (no real hosts or addresses, please) · Vulnerability? [Report privately](SECURITY.md)

[Org file reference](docs/org-file.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [MIT](LICENSE)
