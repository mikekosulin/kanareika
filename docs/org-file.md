# Organization file: `orgs/<id>.yml`

Schema: `assets/schemas/org.schema.json`. Template with comments: `orgs/_template.yml`. Example: `orgs/_example.yml`.
Files starting with `_` are not loaded.

## Sections

| Key | Req. | Meaning |
|---|---|---|
| `org.id` | yes | equals the file name; `a-z0-9_-` |
| `org.name`, `contacts[]`, `owners[]`, `notes` | name | a contact has `name`, `email`, `phone`, `role` |
| `consent.document` | yes | where the signed consent lives |
| `consent.signed`, `consent.valid_until` | yes | no scan outside this interval |
| `consent.external_scan` | no (false) | allows `network_external` |
| `consent.window` | no | `days` (mon..sun), `from`, `to` ("HH:MM"), `tz`; may cross midnight |
| `access.user` | yes | SSH user (ideally the read-only `audit` user) |
| `access.privilege` | no | `none` / `sudo` / `helper` — how root-only reads run (see README) |
| `access.admin_user` | no | account with sudo used by `fix.sh`; default: the SSH user |
| `access.key` | no | key path in `secrets/`; without it the ssh-agent is used |
| `access.known_hosts` | no | pinned host keys in `secrets/`; learned keys go to `reports/<org>/known_hosts` |
| `access.host_key_checking` | no (`accept-new`) | `strict` — connect only to already known keys. A changed key is never accepted |
| `access.port` | no (22) | default SSH port of every host and jump host |
| `access.jumps.<name>` | no | `address`, `port`, `user`, `jump` (chains) |
| `checks` | no | org-level checks (below) |
| `groups.<name>` | yes | `env`, `role`, `exposure`, `jump`, `port` (SSH port of its hosts), `checks`, `hosts` |
| `groups.<g>.hosts.<name>` | yes | `address`, `port`, `user`, `privilege`, `admin_user`, `legacy_ssh` (allow ssh-rsa for an old OpenSSH, this host only), `os`, `exposure`, `jump`, `checks`, `notes` |
| `k8s[]` | no | `name`, `env`, `kubeconfig`, `context`, `namespaces`, `exposure` |
| `external` | no | list of IPs/CIDRs/domains/URLs; with environments a map `env: [list]` |
| `exceptions[]` | no | `id`, `hosts`, `package`, `reason`, `owner`, `review_by`, `until_available` |

SSH port of a host: its `port`, else the one in its `address` (`192.0.2.10:2222`, `[2001:db8::10]:2222`), else the
group's `port`, else `access.port`, else 22. Jump hosts likewise, without the group. A `port` that disagrees with
the address is an error.

Roles (`role`, defaults to the group name): `front`, `app`, `swarm_manager`, `swarm_worker`, `k8s_node`, `mongo`, `internal`.
`exposure`: 1 — perimeter (reachable from the internet), 2 — neighbours, 3 — internal only.

## Environments (`env`)

If an organization has production and staging, set `env` on **every** group. Then `scan`, `history` and `diff`
require `--env`, `--all` makes one run per org and environment, and reports live in `reports/<org>/<env>/`.
`external` and `k8s` are bound to an environment too:

```yaml
external:
  production:
    - shop.example.com
  staging:
    - stage.example.com
```

## Merge order of `checks`

1. `assets/policy/profiles.yml` (or `policy/profiles.yml` next to the data) → `default`
2. the same file → `roles.<group role>`
3. org `checks`
4. `groups.<g>.checks`
5. `groups.<g>.hosts.<h>.checks`

`module: true|false` is short for `enabled`. A mapping without `enabled` only tunes settings. Mappings merge
recursively, **lists are replaced**. `k8s` and `network_external` are allowed only in the org `checks`.
Check the result with `make show ORG=<id>`.

## Module settings and defaults

| Module | Key | Default | Meaning |
|---|---|---|---|
| `os_packages` | `enabled` | true | |
| `software_fs` | `paths` | `/opt /srv /usr/local /home` | where to look |
| | `exclude` | `/var/lib/docker … /tmp` | pruned paths |
| | `patterns`, `max_file_mb`, `max_total_mb` | lockfiles and jars, 100, 1024 | |
| `docker` | `enabled` | false (true for front/app/swarm_*) | |
| | `scan_images` | false | `packages` (recommended), `save`, `registry` |
| | `images` | running | `running` / `all` |
| | `image_parallel`, `max_image_mb` | 2, 4096 | |
| `swarm` / `mongo` | `enabled` | role-dependent | |
| `hardening`, `health`, `access`, `exposure` | `enabled` | true | |
| `network_internal` | `enabled` | false | not implemented |
| `k8s` | `enabled` | false | org `checks` only |
| `network_external` | `enabled`, `ports`, `timing` | false, top 1000, T3 | org `checks` only |

## Priorities and exceptions

`assets/policy/priority.yml` (overridable like the profiles): rules top to bottom, first match wins. Conditions: `kev`, `epss_gte`, `severity`, `exposure`,
`fixable`, `kind`, `kernel`, `preauth`, `rce`, `id`. Due date = scan date + `sla_days[Pn]`.

An exception applies when `id`, the host (if `hosts` is set) and a substring of the package (if `package` is set)
match. After `review_by` it stops applying and the finding returns to the plan, marked as expired.
With `until_available: true` it also stops as soon as the host's repositories offer an update for the package — use
it for "the vendor has not shipped the fix yet": the finding comes back by itself when there is something to install.
`id: "*"` together with `package` covers every CVE of that package (the fix plan for "no fix in the repositories yet"
generates such entries: one per package and host, with `until_available` and a short `review_by`).
