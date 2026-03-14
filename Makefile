.PHONY: build test bench clean lint

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o webguard-mcp ./cmd/webguard-mcp

test:
	go test ./... -v -count=1

bench:
	go test ./internal/classify/... -bench=. -benchmem

bench-real:
	go run ./cmd/benchmark

lint:
	go vet ./...
	staticcheck ./... 2>/dev/null || true

clean:
	rm -f webguard-mcp

install: build
	cp webguard-mcp /usr/local/bin/
