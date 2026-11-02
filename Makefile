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

# Needs .goreleaser.yaml, added in Phase 5.
release-snapshot:
	@command -v goreleaser >/dev/null || { echo "goreleaser not installed: brew install goreleaser"; exit 1; }
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
