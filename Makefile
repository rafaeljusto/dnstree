GO ?= go

# VERSION is what a release build stamps into the binary.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# The platforms a release is built for.
PLATFORMS := \
	darwin/amd64 darwin/arm64 \
	linux/amd64 linux/arm64 linux/arm \
	freebsd/amd64 \
	windows/amd64 windows/arm64

.PHONY: all build install test race vet vuln check live dist clean roothints

all: check

build:
	$(GO) build -ldflags '$(LDFLAGS)' ./...

install:
	$(GO) install -ldflags '$(LDFLAGS)' ./cmd/dnstree

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: build vet race vuln

# Goes out to the real root servers, so it is never part of check.
live:
	$(GO) test -tags live -count=1 ./...

# dist cross compiles a release and archives each build next to its checksum.
dist: clean
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=dnstree; [ "$$os" = windows ] && name=dnstree.exe; \
		echo "building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$name ./cmd/dnstree || exit 1; \
		if [ "$$os" = windows ]; then \
			(cd dist && zip -q dnstree_$(VERSION)_$${os}_$${arch}.zip $$name && rm $$name); \
		else \
			(cd dist && tar czf dnstree_$(VERSION)_$${os}_$${arch}.tar.gz $$name && rm $$name); \
		fi; \
	done
	@(cd dist && shasum -a 256 * > checksums.txt 2>/dev/null || sha256sum * > checksums.txt)
	@ls dist

# Refreshes the embedded root hints and trust anchors.
roothints:
	./scripts/refresh-roothints.sh

clean:
	rm -rf dist
