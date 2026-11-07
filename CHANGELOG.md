# Changelog

Versions follow [Semantic Versioning](https://semver.org). Before 1.0 a minor version may break things; each
break is listed under **Breaking** with what to do instead.

## 0.3.0 — 2026-11-07

One binary, nothing else to install, three interfaces.

### Breaking

- **Commands instead of make targets.** The Makefile is for development only (`bin`, `test`, `cover`, `lint`,
  `check`, `cross`, `clean`). What the old targets did:

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
- **trivy is no longer downloaded or taken from PATH**: the embedded one is used. The old download can be
  removed (`kanareika/bin/` in the user cache directory, e.g. `~/.cache/kanareika/bin` on Linux).
  `KANAREIKA_TRIVY=/path/to/trivy` still selects an external one.

### Added

- **trivy built in** (same version and reports as the official binary), run as `kanareika __trivy`.
  `kanareika db update | status | export | import` downloads the vulnerability DBs and feeds, or moves them
  into an isolated network as one archive; `scan --offline` (`KANAREIKA_OFFLINE=1`) uses only what is there.
- **SSH port** per organization (`access.port`), per group (`port`) and per host (`port` or `host:port`,
  `[v6]:port`); the closest one wins, 22 by default.
- **Terminal interface (TUI), the main one**: `kanareika` with no command. k9s-style, with every tab the web page has:
  ToDo, hosts (Enter: the host card with OS, packages, SSH and logins, ports and firewall, disks, memory, units,
  time), packages, changes since the previous full run, access, network, health, exceptions, runs (`i`: a run's
  errors and log) and scans with a live progress bar. Selecting actions (`v`: the selected only) and copying a fix
  task (OSC 52, works over SSH); starting and stopping scans; the vulnerability DB's age in the header, `U` to
  update it (checked at start: a newer build out, or none yet). It fits small terminals; `o` sets up the panels;
  `L` picks the language; `z` shows times in UTC or the system's zone; hotkeys work on a Cyrillic layout too.
  `kanareika tui --url … --token …` attaches to a remote `kanareika web`.
- **Scans from the web interface**: the same options and consent rules as `kanareika scan`, live output,
  stop. `--no-scans` makes it read-only.
- **Web access beyond localhost** with `--token` (or `KANAREIKA_TOKEN`); without a token it is read-only there.
  Requests are checked for Host (DNS rebinding), Origin and a CSRF token.
- `kanareika init [dir]`, `kanareika version` (with the embedded trivy's), `--home` / `KANAREIKA_HOME`.
- **Chinese (zh)**: findings, actions, fix plans, the agent task, the web page, the TUI and MCP (`lang=zh`).
  The web page has a language menu and starts in the browser's; a button shows times in UTC or the browser's zone.
  Tests check that every string either interface shows is translated in every language.
- **Homebrew**: `brew install mikekosulin/tap/kanareika`; releases update the formula in the tap.
- **GitHub from every interface**: star and report-an-issue links in the web page, the TUI's help and
  `kanareika version`; issue forms (bugs, features) that ask to strip real data; vulnerabilities go to private
  reporting; a pull request template.
- **Screenshots** of the TUI and the web interface in every README language, on made-up data (`tools/demo`).
- **Windows**: binaries in releases; the environment lock uses `LockFileEx`, the ssh-agent is the OpenSSH
  Authentication Agent's pipe (or `SSH_AUTH_SOCK`).

### Fixed

- **Dependencies with known vulnerabilities**: Go 1.27.3 (13 standard library issues on called paths: net/http,
  HTTP/2, crypto/tls, crypto/x509, html/template, os), `golang.org/x/net`, `go-jose`, `klauspost/compress`;
  govulncheck now reports none on called code. trivy is 0.76.2.
- `kanareika validate` printed some schema errors as the validator's raw text with a path on your disk; now
  `access/port: got string, want integer`.

- `tools/anonymize` missed compressed IPv6 addresses and replaced link-local ones only in part, so MAC-derived
  interface ids stayed in test data; they are replaced now, and the test-data guard checks IPv6 too.
- `scan --offline` help showed `db update` as the flag's value.

### Checked

- A test fails when any committable or embeddable file holds a name or address from the local `orgs/`, or a
  data file holds an address (IPv4 or IPv6, including MAC-derived link-local ones) or e-mail that is not a
  documentation one; only `assets/` is embedded in the binary.
- CI tests on Windows and runs a Linux end-to-end check (`tools/e2e/e2e.sh`): the Linux binary scans a real
  sshd container, then `history` and the web API read the result.
- Coverage across the repository is shown as a badge, from every push to `main`.
