# Development only: build and test kanareika. Using it needs nothing but the binary (kanareika --help).
#   make bin     — dist/kanareika for this machine
#   make test    — go vet + go test
#   make cover   — tests with coverage, per function (dist/coverage.html)
#   make lint    — golangci-lint
#   make check   — test + lint
#   make web     — the web page, assets/web/index.html.gz, from web/: lint, format check, build (needs Node and pnpm; the binary does not)
#   make cross   — release binaries for every platform into dist/
#   make clean

BIN := dist/kanareika
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# the embedded trivy reports its own version (otherwise "dev")
TRIVY_VERSION := $(shell go list -m -f '{{.Version}}' github.com/aquasecurity/trivy | sed 's/^v//')
LDFLAGS := -s -w -X main.version=$(VERSION) -X github.com/aquasecurity/trivy/pkg/version/app.ver=$(TRIVY_VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: bin test cover lint check web cross clean FORCE

bin: $(BIN)

# always rebuilt (cheap: go caches); the version comes from git
$(BIN): FORCE
	@CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/kanareika
FORCE:

test:
	go vet ./... && go test ./...

cover:
	@mkdir -p dist
	go test -coverprofile=dist/coverage.out ./...
	go tool cover -func=dist/coverage.out | tail -1
	go tool cover -html=dist/coverage.out -o dist/coverage.html

lint:
	golangci-lint run

check: test lint

web:
	cd web && pnpm install --frozen-lockfile && pnpm run lint && pnpm run fmt:check && pnpm run build

cross:
	@for p in $(PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "dist/kanareika-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/kanareika-$$os-$$arch$$ext ./cmd/kanareika || exit 1; done

clean:
	rm -rf dist
