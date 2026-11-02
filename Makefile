# Kanareika: one native binary (dist/kanareika); every target builds it if needed.
#   make scan ORG=myorg ENV=production       — one environment of an org (ENV is required when there are several)
#   make scan ORG=acme                       — an org with a single environment
#   make scan ORG=acme GROUP=front           — a host group
#   make scan ORG=acme HOST=web-01           — one host
#   make scan ORG=acme MODULE=os_packages    — one module only
#   make scan-all                            — all orgs and environments, one run each
#   make plan ORG=acme                       — like scan, but connects nowhere (dry run)
#   make dashboard                           — dashboard at http://127.0.0.1:8088 (Ctrl+C stops it)
#   make check                               — tests + config validation

BIN := dist/kanareika
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RUN := ./$(BIN)

ENV_ARG = $(if $(ENV),--env $(ENV))
SCAN_ARGS = --org $(ORG) $(ENV_ARG) $(if $(GROUP),--group $(GROUP)) $(if $(HOST),--host $(HOST)) $(if $(MODULE),--module $(MODULE)) $(ARGS)

.PHONY: bin test lint check validate show scan scan-all plan history diff prune feeds dashboard helper new-org migrate require-org

bin: $(BIN)

# always rebuilt (cheap: go caches); the version comes from git
$(BIN): FORCE
	@CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/kanareika
FORCE:

test:
	go vet ./... && go test ./...

lint:
	golangci-lint run

check: test validate   ## before using a new version: tests, config validation

validate: bin
	$(RUN) validate $(if $(ORG),--org $(ORG))

show: bin require-org
	$(RUN) show --org $(ORG)

scan: bin require-org
	$(RUN) scan $(SCAN_ARGS)

plan: bin require-org
	$(RUN) scan --dry-run $(SCAN_ARGS)

scan-all: bin
	$(RUN) scan --all $(ARGS)

history: bin require-org
	$(RUN) history --org $(ORG) $(ENV_ARG)

diff: bin require-org
	$(RUN) diff --org $(ORG) $(ENV_ARG) $(if $(FROM),--from $(FROM)) $(if $(TO),--to $(TO))

prune: bin
	$(RUN) prune $(if $(ORG),--org $(ORG)) $(ARGS)

feeds: bin
	$(RUN) feeds

migrate: bin   ## rewrite org files in the current format (DRY=1: show only)
	$(RUN) migrate $(if $(DRY),--dry-run)

dashboard: bin
	$(RUN) serve $(ARGS)

helper: bin   ## root helper for servers -> provisioner role (path: PROVISIONER=...)
	@test -n "$(PROVISIONER)" || (echo "set PROVISIONER=<path to provisioner repo>" && exit 1)
	$(RUN) helper > $(PROVISIONER)/roles/audit_user/files/kanareika-collect
	@echo "kanareika-collect updated in the audit_user role. Roll out: ansible-playbook audit.yml"

new-org: require-org
	@test ! -e orgs/$(ORG).yml || (echo "orgs/$(ORG).yml already exists" && exit 1)
	@echo "$(ORG)" | grep -Eq '^[a-z0-9][a-z0-9_-]*$$' || (echo "ORG: only a-z, 0-9, '-', '_'" && exit 1)
	sed 's/__ORG_ID__/$(ORG)/g' orgs/_template.yml > orgs/$(ORG).yml
	mkdir -p secrets/$(ORG) && chmod 700 secrets/$(ORG)
	@echo "Created orgs/$(ORG).yml and secrets/$(ORG)/. Fill it in, then: make validate ORG=$(ORG)"

require-org:
	@test -n "$(ORG)" || (echo "Specify ORG=<id>. For all organizations: make scan-all" && exit 1)
