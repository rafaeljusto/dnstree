GO ?= go

# golangci-lint comes from the PATH when it is there, and is fetched at the
# pinned version when it is not.
GOLANGCI_LINT_VERSION ?= v2.13.2
HADOLINT_VERSION ?= v2.15.1
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || \
	echo "$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)")

# VERSION is what a release build stamps into the binary.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Where the image is published, and what a release is built for.
IMAGE ?= ghcr.io/rafaeljusto/dnstree
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
VCS_REF ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# The platforms a release is built for.
PLATFORMS := \
	darwin/amd64 darwin/arm64 \
	linux/amd64 linux/arm64 linux/arm \
	freebsd/amd64 \
	windows/amd64 windows/arm64

.PHONY: all build install test race lint lint-docker vuln check live dist image image-push clean roothints

all: check

build:
	$(GO) build -ldflags '$(LDFLAGS)' ./...

install:
	$(GO) install -ldflags '$(LDFLAGS)' ./cmd/dnstree

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

# go vet is not covered by golangci-lint: its bundled govet ships a different
# set of analysers, and misses appends and slog among others.
lint:
	$(GO) vet ./...
	$(GOLANGCI_LINT) run ./...

# hadolint runs from its own image, so there is nothing to install.
lint-docker:
	docker run --rm -i hadolint/hadolint:$(HADOLINT_VERSION) < Dockerfile

# Separate from lint: this one goes red when somebody else publishes a CVE,
# not when this code changes.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: build lint race vuln

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

# image builds for this machine; image-push builds for every platform and
# publishes, which is what a release does.
image:
	docker buildx build \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg BUILD_VCS_REF=$(VCS_REF) \
		--build-arg BUILD_VERSION=$(VERSION) \
		--tag $(IMAGE):$(VERSION) \
		--load \
		.

image-push:
	docker buildx build \
		--platform $(IMAGE_PLATFORMS) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg BUILD_VCS_REF=$(VCS_REF) \
		--build-arg BUILD_VERSION=$(VERSION) \
		--tag $(IMAGE):$(VERSION) \
		--tag $(IMAGE):latest \
		--push \
		.

# Refreshes the embedded root hints and trust anchors.
roothints:
	./scripts/refresh-roothints.sh

clean:
	rm -rf dist
