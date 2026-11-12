BINARY := plugger
BUILD_DIR := bin
MODULE := github.com/illumio/plugger
VERSION ?= dev
LDFLAGS := -ldflags "-X $(MODULE)/internal/cli.Version=$(VERSION)"

.PHONY: build test lint clean install snapshot

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/plugger

# Full release build into dist/ without publishing: binaries, SHA256SUMS,
# .deb/.rpm and the Homebrew formula (needs goreleaser).
snapshot:
	HOMEBREW_TAP_TOKEN=unused goreleaser release --snapshot --clean

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY) $(GOPATH)/bin/$(BINARY)
