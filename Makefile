.PHONY: build test bench clean lint release

VERSION ?= 0.2.0
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

release: test build
	@CHECKSUM=$$(shasum -a 256 webguard-mcp | cut -d' ' -f1); \
	echo "Version: v$(VERSION)"; \
	echo "SHA-256: $$CHECKSUM"; \
	git tag -a v$(VERSION) -m "v$(VERSION)$$(echo; echo; git log --oneline $$(git describe --tags --abbrev=0 2>/dev/null || echo HEAD~5)..HEAD)$$(echo; echo "Binary checksum (darwin/arm64):"; echo "SHA-256: $$CHECKSUM")"; \
	git push origin v$(VERSION); \
	gh release create v$(VERSION) ./webguard-mcp \
		--title "v$(VERSION)" \
		--generate-notes \
		--notes-start-tag "$$(git tag --sort=-v:refname | sed -n '2p')" ; \
	echo "Released: https://github.com/mark-liu/webguard-mcp/releases/tag/v$(VERSION)"
