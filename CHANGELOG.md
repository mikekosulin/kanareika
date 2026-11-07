# Changelog

Versions follow [Semantic Versioning](https://semver.org). Before 1.0 a minor version may break things; each
break is listed under **Breaking** with what to do instead.

## 0.3.0

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
- **Terminal interface (TUI)**, in the style of k9s: organizations, to-do list, hosts, packages, runs and scans,
  filters, selection, copying a fix task to the clipboard (OSC 52, works over SSH), and starting and stopping
  scans. It fits small terminals (columns size to their content, the header folds to one line), and `o` sets up the
  panels (header, P4, columns per view), kept in the user config directory. `kanareika tui --url … --token …`
  attaches to a remote `kanareika web`.
- **Scans from the web interface**: the same options and consent rules as `kanareika scan`, live output,
  stop. `--no-scans` makes it read-only.
- **Web access beyond localhost** with `--token` (or `KANAREIKA_TOKEN`); without a token it is read-only there.
  Requests are checked for Host (DNS rebinding), Origin and a CSRF token.
- `kanareika init [dir]`, `kanareika version` (with the embedded trivy's), `--home` / `KANAREIKA_HOME`.
- **Chinese (zh)**: findings, actions, fix plans, the agent task, the web page, the TUI and MCP (`lang=zh`).
  The web page cycles through every language and starts in the browser's.
- **Windows**: binaries in releases; the environment lock uses `LockFileEx`, the ssh-agent is the OpenSSH
  Authentication Agent's pipe (or `SSH_AUTH_SOCK`).

### Fixed

- `tools/anonymize` missed compressed IPv6 addresses and replaced link-local ones only in part, so MAC-derived
  interface ids stayed in test data; they are replaced now, and the test-data guard checks IPv6 too.
- `scan --offline` help showed `db update` as the flag's value.

### Checked

- A test fails when any committable or embeddable file holds a name or address from the local `orgs/`, or a
  data file holds an address or e-mail that is not a documentation one; only `assets/` is embedded in the
  binary.
- CI tests on Windows and runs a Linux end-to-end check (`tools/e2e/e2e.sh`): the Linux binary scans a real
  sshd container, then `history` and the web API read the result.
