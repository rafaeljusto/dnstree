GO ?= go

.PHONY: all build test race vet vuln check clean roothints

all: check

build:
	$(GO) build ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: build vet race vuln

# Refreshes the embedded root hints and trust anchors.
roothints:
	./scripts/refresh-roothints.sh

clean:
	$(GO) clean ./...
