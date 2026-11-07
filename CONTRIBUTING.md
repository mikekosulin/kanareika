# Contributing

Thanks for helping. Bug reports, fixes and new checks are welcome; for larger changes open an issue first so we can
agree on the approach. Security issues go through [SECURITY.md](SECURITY.md), not issues.

## Setup

You need Go (the version in `go.mod`) and, for linting, [golangci-lint](https://golangci-lint.run) v2.

```bash
make bin      # dist/kanareika
make test     # go vet + go test
make lint     # golangci-lint
make cover    # coverage per function, dist/coverage.html
```

CI also runs `gofmt` and `go test -race`; run `gofmt -l cmd internal assets tools` before pushing. It tests on
Windows too, and runs the Linux end-to-end check: `tools/e2e/e2e.sh` (needs Docker; downloads the vulnerability DB,
about 1 GB on the host) builds the Linux binary, scans a Debian container over SSH and reads the result through
`history` and the web API. Everything in it is made up and removed afterwards.

## Test data must be fake

Test data captured from real hosts is the easiest way to leak someone's infrastructure. Everything under `testdata/`
may only hold fake addresses, names and e-mails:

- addresses: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `2001:db8::/32`, or what
  `tools/anonymize` maps to; e-mails at `example.com` / `*.example`;
- names: neutral placeholders (`acme`, `host-01`, `web-01`, `alice`, `bob`), never real companies, projects or people;
- run real captures through `go run ./tools/anonymize <dir>` and review the diff; raw captures that must stay real go
  to `testdata/local/` (git-ignored).

The guard in `tools/anonymize` runs with `go test ./...`:

- `TestNoRealData` checks every file that is or could be committed: data files (testdata, the assets embedded into
  the binary, docs, examples) may only hold fake addresses and e-mails, and no file may contain a name or address
  from your local `orgs/*.yml` (org ids and names, hosts, addresses, jump hosts, external targets, the consent
  document). Your org files never leave your machine, and neither does that list: the check runs where leaks are
  made. More forbidden strings: `KANAREIKA_DENYLIST=<file with one string per line> go test ./tools/anonymize/`;
- `TestEmbedsOnlyAssets` fails on any `//go:embed` outside `assets/` (policy, schemas, locales, web, templates), so nothing
  else can be built into the binary.

## Pull requests

- one topic per PR, with tests; keep golden files in sync with the change;
- commit messages in [Conventional Commits](https://www.conventionalcommits.org) style (`feat:`, `fix:`, `docs:`,
  `test:`, `ci:`, `deps:`), imperative mood; the PR is squash-merged with its title as the commit message;
- commits on `main` must be signed — GitHub signs the squash commit, so your branch commits need not be;
- CI (`test`, `lint`) must pass and review threads must be resolved before merge.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
