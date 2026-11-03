VERSION ?= v0.0.1
BIN     := bin/shorstop
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test lint bench release-snapshot clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/shorstop

test:
	go vet ./...
	go test -race ./...

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed: brew install golangci-lint"; exit 1; }
	golangci-lint run

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Builds every release archive into dist/ without publishing. Signing and
# SBOMs need cosign and syft, which only the release workflow installs.
release-snapshot:
	@command -v goreleaser >/dev/null || { echo "goreleaser not installed: go install github.com/goreleaser/goreleaser/v2@latest"; exit 1; }
	goreleaser release --snapshot --clean --skip=sign,sbom

clean:
	rm -rf bin dist
