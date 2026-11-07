#!/usr/bin/env bash
# Linux end-to-end check: the Linux binary scans a real host over SSH and every interface reads the result.
#
#   tools/e2e/e2e.sh           (needs docker, ssh-keygen, curl; downloads the vulnerability DB)
#
# A Debian container with sshd is the target; kanareika runs in a second Debian container on the same network,
# so the check is the same on a Linux CI runner and on a developer's Mac. Nothing real: the org, its contacts
# and the host are made up here and removed afterwards.
set -euo pipefail
cd "$(dirname "$0")/../.."

id="kn-e2e-$$"
work="$(mktemp -d)"
cleanup() {
	docker rm -f "$id-target" "$id-runner" >/dev/null 2>&1 || true
	docker network rm "$id" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

arch="$(docker version -f '{{.Server.Arch}}')"
step "build kanareika for linux/$arch"
trivy="$(go list -m -f '{{.Version}}' github.com/aquasecurity/trivy | sed 's/^v//')"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
	-ldflags "-s -w -X main.version=e2e -X github.com/aquasecurity/trivy/pkg/version/app.ver=$trivy" \
	-o "$work/kanareika" ./cmd/kanareika

step "target: debian with sshd"
ssh-keygen -q -t ed25519 -N "" -C e2e -f "$work/key"
docker network create "$id" >/dev/null
docker build -q -t kanareika-e2e-target -f tools/e2e/target.Dockerfile tools/e2e >/dev/null
docker run -d --name "$id-target" --network "$id" --network-alias target-01 \
	-v "$work/key.pub:/key.pub:ro" kanareika-e2e-target >/dev/null

step "runner: debian with the binary"
mkdir -p "$work/home" "$work/cache" "$work/tmp"
# the caches and temp files (vulnerability DB ~1 GB) live on the host, not in the container's layer
docker run -d --name "$id-runner" --network "$id" -p 127.0.0.1::8088 \
	-v "$work/kanareika:/usr/local/bin/kanareika:ro" -v "$work/home:/work" -v "$work/cache:/root/.cache" -v "$work/tmp:/tmp" -w /work \
	-e KANAREIKA_HOME=/work debian:12-slim sleep infinity >/dev/null
docker exec "$id-runner" sh -c 'apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null'
k() { docker exec "$id-runner" kanareika "$@"; }

step "init, org, validate"
k version
k init .
k org new e2e
install -m 600 "$work/key" "$work/home/secrets/e2e_key"
today="$(date -u +%F)"
until="$(date -u -d '+30 days' +%F 2>/dev/null || date -u -v+30d +%F)"
cat >"$work/home/orgs/e2e.yml" <<YML
org:
  id: e2e
  name: "End-to-end check"
  contacts:
    - name: Test Admin
      email: admin@example.com
      role: admin
consent:
  document: "e2e"
  signed: $today
  valid_until: $until
  window:
    days: [mon, tue, wed, thu, fri, sat, sun]
    from: "00:00"
    to: "23:59"
    tz: UTC
access:
  user: audit
  key: e2e_key
  privilege: none
  host_key_checking: accept-new
groups:
  app:
    role: app
    exposure: 3
    hosts:
      target-01:
        address: target-01:22
YML
k validate e2e
k show e2e

step "db update (vulnerability DB download)"
k db update
k db status

step "scan"
k scan e2e --ignore-window
run="$(ls "$work/home/reports/e2e/default" | grep -v current | tail -1)"
[ -n "$run" ] || fail "no run directory"
rj="$work/home/reports/e2e/default/$run/run.json"
grep -q '"finished": "20' "$rj" && grep -q '"hosts_ok": 1,' "$rj" && grep -q '"hosts_failed": {}' "$rj" \
	|| fail "run not finished cleanly: $(cat "$rj")"
sbom="$(find "$work/home/reports/e2e/default/$run" -name sbom.cdx.json | head -1)"
[ -n "$sbom" ] || fail "no SBOM: os_packages did not run"
n="$(grep -o '"purl"' "$sbom" | wc -l)"
[ "$n" -gt 50 ] || fail "SBOM has $n packages"
echo "packages in the SBOM: $n"

step "history, diff"
k history e2e
k diff e2e || true

step "web API"
docker exec -d "$id-runner" kanareika web --host 0.0.0.0 --token e2e-token
port="$(docker port "$id-runner" 8088/tcp | head -1 | sed 's/.*://')"
for _ in $(seq 50); do curl -fsS -o /dev/null "http://127.0.0.1:$port/api/orgs" -H "Authorization: Bearer e2e-token" 2>/dev/null && break; sleep 0.2; done
curl -fsS "http://127.0.0.1:$port/api/orgs" -H "Authorization: Bearer e2e-token" | grep -q '"id":"e2e"' || fail "web: org not listed"
curl -fsS "http://127.0.0.1:$port/api/run?org=e2e&env=default&run=current" -H "Authorization: Bearer e2e-token" | grep -q '"target-01"' || fail "web: host not in the current state"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/orgs")"
[ "$code" = 401 ] || fail "web without the token answered $code"

printf '\nOK: linux/%s end to end\n' "$arch"
