# Changelog

Versions follow [Semantic Versioning](https://semver.org). Before 1.0 a minor version may break things; each break is listed under **Breaking** with what to do instead.

## 0.5.0 — 2026-11-XX

What to fix, grouped the way it gets fixed; a new web page and TUI; setup for a homelab, a client or a fleet.

### Breaking

- **Due dates count from the first scan that saw a finding** (`first_seen`), not from every scan, and are never later than CISA's KEV due date. Long-open findings may now show as overdue. To change it, set `due:` in `assets/policy/priority.yml` or in the org file, per environment too (`start: scan` restores the old count); see [Due dates](docs/org-file.md#due-dates).
- **TUI views are renumbered**: `1` ToDo, `2` Hosts … `9` Runs, `0` Scans. The Organizations view is gone: pick an organization with `O`, an environment with `E`. The status bar replaces the header, so the `header` setting is ignored.
- **The 0.4 web page moved to `/classic`**; `/` is the new one, and `/index.html` redirects to `/`.
- **`db update` and scans ask before downloading** on a terminal, with the size. In scripts nothing changes (no terminal, no question); otherwise pass `--yes` (`-y`) or set `KANAREIKA_YES=1`.
- **The Java DB (about 1 GB) is downloaded only when a scan first finds .jar files.** To have it in advance, e.g. before `db export` for an isolated network, run `kanareika db update --java`.
- **Release assets are archives**: `kanareika-<OS>-<ARCH>.tar.xz` (`.zip` on Windows), about a fifth of the binary's size. The bare binaries are still published with this release only; switch download links and scripts to the archives.

### Added

- **The vulnerability tree**: findings grouped by fix (one package update on many hosts, one image to rebuild, with where it runs), by CVE or by host; per group the hosts, CVEs, max EPSS, KEV/RCE, fix states and the earliest due date. A node's details say why its priority, where the due date comes from (`due_why`), every CVE with its CVSS vector, EPSS, KEV and description, and the commands per OS family. The web page, the TUI and MCP show the same tree (`/api/tree`, `/api/node`).
- **A new web page** on the tree, with first-run setup and scans from the page; `⌘K` / `Ctrl+K` opens a command palette.
- **The TUI's ToDo is the tree**, with a details pane, a status bar, organization and environment pickers (`O`, `E`), filters (`f`) and `:` to jump to a fix, a CVE, a host or a view.
- **Context for AI agents**: `Y` in the TUI copies one node's context for an agent's chat, `y` the task for the selection; `/api/prompt?nodes=`; MCP `list_fixes` and `get_fix`.
- **Setup for every case**: my servers (homelab), a client's servers (one org per client) or a fleet. One field takes IPs, `user@host`, ssh command lines, `~/.ssh/config` blocks and aliases, CSV and Ansible inventories, and shows live what each line becomes; `~/.ssh/config` hosts can be picked from a list. Servers can be added to an existing org (the old file kept as `.bak`). The access check runs per host and groups failures by cause, with what to do. The TUI has the same setup.
- **The download question shows real sizes**, read from the registries (`/api/db/size`).
- **The web page on any port**: `--port` or `KANAREIKA_PORT`, `--port 0` for a free one; `--host` or `KANAREIKA_HOST`. It still listens on localhost by default. A busy port gets a plain message.
- **install.sh**: picks the build for this OS and CPU, checks its checksum and the build attestation (with the GitHub CLI), asks before installing. Read it before running it; the README shows how.
- **Code of Conduct** (Contributor Covenant 2.1, adapted), an **AI policy** for contributions, and a social preview that reads at link-preview size.

### Changed

- **Scans refresh KEV and EPSS** when they are older than a day, and say so when they run without them; `--offline` warns about a vulnerability DB older than a week.
- **The demo** is a fleet of 118 hosts in groups, with shared advisories, updates rolling out per group, kernels waiting for a reboot, and images in Docker and Kubernetes.
- **The remaining web views** are redrawn in the new design.
- **DB downloads run in parallel**, with progress per download and in total.
- **Counts agree** between the web page, the TUI and MCP, "no access" messages say plainly what could not be read, and findings waiting for a vendor fix are counted.

### Fixed

- **No telemetry from the embedded trivy**: `--skip-version-check` alone still sent anonymous usage data with the version check. Every trivy run now has telemetry and the version check switched off.
- **`kanareika org new`** dates the consent today, valid for a year: the template's `valid_until: 2027-01-01` would have stopped every new org on that day.
- **Pasted host lists**: impossible IPv4 addresses (`10.0.0.300`, `10.0.0`) and CSV header lines are skipped instead of becoming hosts; pasted `~/.ssh/config` aliases are written out with their HostName, Port, User and ProxyJump, as ssh would resolve them.

## 0.4.0 — 2026-11-08

Five more languages, and the interfaces say plainly what they show.

### Added

- **Español, Français, Português, 日本語, 한국어** alongside English, Русский and 中文: findings, actions, fix plans, the agent task, the web page, the TUI and MCP (`lang=es`, …). Each translation was reviewed against well-localized tools of the same field (Cockpit, Grafana, the national CERTs' wording). Language menus list them as language switchers usually do: English, then by their own names.
- **A README in every language** (`docs/readme/`), each with its banner and screenshots, and a test that keeps every README's links, pictures and language switcher whole.
- **TUI hotkeys on the Korean 2-set and French AZERTY layouts** (on AZERTY the views switch with `1`–`0` without Shift), as on the Russian one.
- **`?lang=` on the web page** opens it in a language: a link to share.
- **Tools for the pictures**: `go run ./tools/screenshots -out docs/screenshots` draws the TUI and the web page in every language over the demo data; `go run ./tools/brand` the README banners and the social preview.
- **SECURITY.md** says where Kanareika's vulnerabilities are published (its GitHub Security Advisories), and that generated "CVE" pages elsewhere are not.

### Changed

- **The TUI's header**: `Trivy` is the version built into the server ("0.76.2 built in"), and the run's own only when it differs; before the first run it was "-", which read as trivy missing. `DB` says "up to date" while no newer build is due.
- **Interface texts are whole sentences** with `{placeholders}` instead of pieces glued in code, so each language orders its words ("hace 5 min", "il y a 5 min"). The agent task, the fix plan's labels and each language's name moved into the locale files, where the tests check them too, including the rule that host data is data, not instructions.
- **Release notes** are the version's CHANGELOG section.
- **The demo** uses CVE ids of the year 0000, which are never assigned: the made-up `CVE-2026-9xxxx` had become real ids as 2026's numbers came up. It also brings a trivy cache of its own (`TRIVY_CACHE_DIR=<demo>/trivy`).

### Fixed

- **Kernel-owned ports (VXLAN: udp/4789 of Docker Swarm, udp/8472 of flannel)** are closed in `INPUT`: the fix plan put them in `DOCKER-USER`, which their packets never pass.
- **Other findings on a host card** were in English whatever the language: their rows lost the message key.
- **The DB's age** could be negative ("-392m") when the clock was behind the DB's build time.
- **A Docker access error** was in Russian in every language.
- The coverage badge stopped updating (its workflow file was kept out of the repository by an ignore rule).

## 0.3.0 — 2026-11-07

One binary, nothing else to install, three interfaces.

### Breaking

- **Commands instead of make targets.** The Makefile is for development only (`bin`, `test`, `cover`, `lint`, `check`, `cross`, `clean`). What the old targets did:

  | before                                  | now                                              |
  |-----------------------------------------|--------------------------------------------------|
  | `make scan ORG=acme ENV=production`     | `kanareika scan acme --env production`           |
  | `make scan ... GROUP= HOST= MODULE=`    | `--group`, `--host`, `--module` (repeatable)     |
  | `make plan ORG=acme`                    | `kanareika scan acme --dry-run`                  |
  | `make scan-all`                         | `kanareika scan --all`                           |
  | `make validate` / `make show ORG=`      | `kanareika validate` / `kanareika show acme`     |
  | `make history` / `diff` / `prune`       | `kanareika history` / `diff` / `prune`           |
  | `make feeds`                            | `kanareika db update` (`feeds`: deprecated)      |
  | `make migrate` / `make helper`          | `kanareika migrate` / `kanareika helper -o FILE` |
  | `make new-org ORG=acme`                 | `kanareika org new acme`                         |
  | `make dashboard`                        | `kanareika web`                                  |

- **`kanareika serve` is `kanareika web`.** `serve` and `dashboard` remain as aliases.
- **`kanareika` with no command opens the terminal interface** in a terminal (help otherwise, e.g. in scripts).
- **The org template moved** from `orgs/_template.yml` into the binary: `kanareika org new <id>` writes it.
- **trivy is no longer downloaded or taken from PATH**: the embedded one is used. The old download can be removed (`kanareika/bin/` in the user cache directory, e.g. `~/.cache/kanareika/bin` on Linux). `KANAREIKA_TRIVY=/path/to/trivy` still selects an external one.

### Added

- **trivy built in** (same version and reports as the official binary), run as `kanareika __trivy`. `kanareika db update | status | export | import` downloads the vulnerability DBs and feeds, or moves them into an isolated network as one archive; `scan --offline` (`KANAREIKA_OFFLINE=1`) uses only what is there.
- **SSH port** per organization (`access.port`), per group (`port`) and per host (`port` or `host:port`, `[v6]:port`); the closest one wins, 22 by default.
- **Terminal interface (TUI), the main one**: `kanareika` with no command. k9s-style, with every tab the web page has: ToDo, hosts (Enter: the host card with OS, packages, SSH and logins, ports and firewall, disks, memory, units, time), packages, changes since the previous full run, access, network, health, exceptions, runs (`i`: a run's errors and log) and scans with a live progress bar. Selecting actions (`v`: the selected only) and copying a fix task (OSC 52, works over SSH); starting and stopping scans; the vulnerability DB's age in the header, `U` to update it (checked at start: a newer build out, or none yet). It fits small terminals; `o` sets up the panels; `L` picks the language; `z` shows times in UTC or the system's zone; hotkeys work on a Cyrillic layout too. `kanareika tui --url … --token …` attaches to a remote `kanareika web`.
- **Scans from the web interface**: the same options and consent rules as `kanareika scan`, live output, stop. `--no-scans` makes it read-only.
- **Web access beyond localhost** with `--token` (or `KANAREIKA_TOKEN`); without a token it is read-only there. Requests are checked for Host (DNS rebinding), Origin and a CSRF token.
- `kanareika init [dir]`, `kanareika version` (with the embedded trivy's), `--home` / `KANAREIKA_HOME`.
- **Chinese (zh)**: findings, actions, fix plans, the agent task, the web page, the TUI and MCP (`lang=zh`). The web page has a language menu and starts in the browser's; a button shows times in UTC or the browser's zone. Tests check that every string either interface shows is translated in every language.
- **Homebrew**: `brew install mikekosulin/tap/kanareika`; the tap follows new releases by itself.
- **GitHub from every interface**: star and report-an-issue links in the web page, the TUI's help and `kanareika version`; issue forms (bugs, features) that ask to strip real data; vulnerabilities go to private reporting; a pull request template.
- **Screenshots** of the TUI and the web interface in every README language, on made-up data (`tools/demo`).
- **Windows**: binaries in releases; the environment lock uses `LockFileEx`, the ssh-agent is the OpenSSH Authentication Agent's pipe (or `SSH_AUTH_SOCK`).

### Fixed

- **Dependencies with known vulnerabilities**: Go 1.27.3 (13 standard library issues on called paths: net/http, HTTP/2, crypto/tls, crypto/x509, html/template, os), `golang.org/x/net`, `go-jose`, `klauspost/compress`; govulncheck now reports none on called code. trivy is 0.76.2.
- **Run from Windows**: a link to an absolute path inside a host's archive (`/etc/passwd`) was not refused and could point outside the unpacking directory; saved Docker images were not checked (removed while still open); software_fs paths came out with `\`. Fix tasks and MCP results now mark what hosts report as data, not instructions to an agent.
- A jump host reached again through its own jumps (possible only in a hand-built configuration) hung the scan; it is an error now. A name resolved to an IPv4-mapped address showed as `::ffff:…` in findings and nmap's command line.
- `kanareika validate` printed some schema errors as the validator's raw text with a path on your disk; now `access/port: got string, want integer`.

- `tools/anonymize` missed compressed IPv6 addresses and replaced link-local ones only in part, so MAC-derived interface ids stayed in test data; they are replaced now, and the test-data guard checks IPv6 too.
- `scan --offline` help showed `db update` as the flag's value.

### Checked

- A test fails when any committable or embeddable file holds a name or address from the local `orgs/`, or a data file holds an address (IPv4 or IPv6, including MAC-derived link-local ones) or e-mail that is not a documentation one; only `assets/` is embedded in the binary.
- CI tests on Windows and runs a Linux end-to-end check (`tools/e2e/e2e.sh`): the Linux binary scans a real sshd container, then `history` and the web API read the result.
- Every statement is covered by tests (100%, measured per package and across the repository); the tests never read the user's trivy cache, feeds or home directories. Coverage is shown as a badge, from every push to `main`.
