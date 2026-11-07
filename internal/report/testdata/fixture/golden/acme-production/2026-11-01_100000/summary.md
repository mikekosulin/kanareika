# acme / production — scan 2026-11-01_100000

- Hosts: 3 ok, 1 failed
- Modules: access, docker, exposure, hardening, health, os_packages, software_fs, network_external
- Trivy 0.58.0, KEV/EPSS as of none (kanareika db update)

| | P1 | P2 | P3 | P4 | accepted |
|---|---:|---:|---:|---:|---:|
| packages to update | 4 | 12 | 18 | 3 | |
| findings (CVE × package) | 5 | 18 | 22 | 5 | 2 |

Already fixed in the installed build (CVE in the package changelog, not counted above): 2

## Errors

- **dead-01**: ssh: connection refused

- app-01: docker: boom
- app-01: hardening: x

## Update plan

### web-01

| prio | due | package | where | installed | fixed in | repositories | CVE | KEV |
|---|---|---|---|---|---|---|---:|---|
| P1 | 2026-11-08 | openssl | os | 3.0.1 | 3.0.10 | update to 3.0.10-1 | 3 | yes |
| P1 | 2026-11-08 | rsync | os | 3.2.3 | 3.2.8 | no fix yet | 3 |  |
| P1 | 2027-01-30 | kernel-modules | os | 5.14.0-575.el9 | 5.14.0-600.el9 | installed, reboot into 5.14.0-759.el9 | 1 | yes |
| P2 | 2027-01-30 | kernel-core | os | 5.14.0-575.el9 | 5.14.0-600.el9 | installed, reboot into 5.14.0-759.el9 | 1 |  |
| P2 | 2027-01-30 | lib0 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P2 | 2027-01-30 | lib1 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P2 | 2027-01-30 | lib2 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib3 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib4 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib5 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib6 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib7 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | vim | os | 8.2 | 9.0 |  | 1 |  |
| P4 | 2027-04-30 | glibc | os | 2.34-1 | no fix |  | 1 |  |
| P4 | 2027-01-30 | kernel-core | os: old kernel | 5.14.0-500.el9 | 5.14.0-600.el9 |  | 1 |  |
| P4 | 2027-01-30 | kernel-core | os: new kernel (reboot pending) | 5.14.0-759.el9 | 5.14.0-800.el9 |  | 1 |  |

### app-01

| prio | due | package | where | installed | fixed in | repositories | CVE | KEV |
|---|---|---|---|---|---|---|---:|---|
| P1 | 2027-01-30 | nginx | image:nginx:1.25 | 1.25.0 | 1.25.5 |  | 1 | yes |
| P2 | 2027-01-30 | lib0 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P2 | 2027-01-30 | lib1 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P2 | 2027-01-30 | lib2 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib3 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib4 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib5 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib6 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | lib7 | image:registry.example/team/api:1.2@sha256:abcd | 1 | 2 |  | 1 |  |
| P3 | 2027-01-30 | npm-0 | /opt/app/package-lock.json | 1.0.0 | 1.0.1 |  | 1 |  |
| P3 | 2027-01-30 | npm-1 | /opt/app/package-lock.json | 1.0.0 | 1.0.1 |  | 1 |  |
| P3 | 2027-01-30 | npm-2 | /opt/app/package-lock.json | 1.0.0 | 1.0.1 |  | 1 |  |

### db-01

| prio | due | package | where | installed | fixed in | repositories | CVE | KEV |
|---|---|---|---|---|---|---|---:|---|
| P2 | 2026-12-01 | libssl3 | os | 1.0 | 1.9 |  | 3 |  |
| P2 | 2026-12-01 | bash | os | 1.0 | 1.15 |  | 1 |  |
| P2 | 2027-01-30 | linux-image-6.1.0-18-amd64 | os | 6.1.76-1 | 6.1.90-1 |  | 1 |  |
| P2 | 2026-12-01 | tar | os | 1.0 | 1.13 |  | 1 |  |
| P2 | 2026-12-01 | zlib1g | os | 1.0 | 1.11 |  | 1 |  |
| P3 | 2026-12-01 | gzip | os | 1.0 | 1.14 |  | 1 |  |
| P3 | 2026-12-01 | libc6 | os | 1.0 | 1.10 |  | 1 |  |
| P3 | 2026-12-01 | libxml2 | os | 1.0 | 1.12 |  | 1 |  |
| P3 | 2026-12-01 | perl-base | os | 1.0 | 1.16 |  | 1 |  |

## Configuration, exposure, health

| prio | host | id | what | details |
|---|---|---|---|---|
| P1 | app-01 | os-eol | Migrate off Ubuntu 18.04 | the OS is end-of-life |
| P2 | db-01 | listen-public-53-tcp | Close dns :53 to the outside | tcp *:53 named |
| P2 | db-01 | listen-public-53-udp | Close dns :53 to the outside | udp *:53 named |
| P2 | web-01 | ssh-password-auth | Disable SSH password login | PasswordAuthentication yes |
| P3 | db-01 | ssh-password-auth | Disable SSH password login | PasswordAuthentication yes (Match) |
| P4 | external:203.0.113.10 | ext-open-443 | Port 443 is open | 203.0.113.10:443 |
| P4 | web-01 | journal-errors | Look into journal errors | Ошибки в журнале: жжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжжж |
| - | app-01 | custom-check | Something without a message key |  |

## Exceptions

| host | id | package | until | status | reason |
|---|---|---|---|---|---|
| web-01 | CVE-2026-0040 | curl | 2027-01-01 | accepted | no internet |
| web-01 | CVE-2026-0041 | vim | 2026-10-01 | EXPIRED — back in the plan | later |
| web-01 | CVE-2026-0042 | rsync | 2027-01-01 | fix arrived in the repositories — back in the plan | until fixed |
| app-01 | ssh-root-login |  | 2027-01-01 | accepted | legacy |
