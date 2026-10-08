GO ?= go
# node runs the pages' tests, and needs to be 22 or later.
NODE ?= node

# golangci-lint comes from the PATH when it is there, and is fetched at the
# pinned version when it is not.
GOLANGCI_LINT_VERSION ?= v2.13.2
HADOLINT_VERSION ?= v2.15.1
NFPM_VERSION ?= v2.47.0

# vhs records the terminal demos. It is pinned and always run through `go run`
# rather than taken from the PATH: 0.12.0 hands its own cancelled context to
# the ffmpeg step, so it captures every frame, writes nothing, and exits 0.
# vhs shells out to ttyd and ffmpeg, which do have to be installed.
VHS_VERSION ?= v0.10.0
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || \
	echo "$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)")
NFPM ?= $(shell command -v nfpm 2>/dev/null || \
	echo "$(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)")
VHS ?= $(GO) run github.com/charmbracelet/vhs@$(VHS_VERSION)

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

# The architectures make web-lambda builds a zip for.
LAMBDA_ARCHES ?= arm64 amd64

# The native packages a release carries, as GOARCH:nfpm arch. nfpm translates
# the right hand side per format, so arm7 lands as armhf on Debian, armv7hl on
# RPM and armv7 on Alpine.
PKG_FORMATS ?= deb rpm apk
PKG_ARCHES ?= amd64:amd64 arm64:arm64 arm:arm7

# nfpm reads the version as semver, which `git describe` on an untagged tree is
# not. A build without a tag packages as 0.0.0; a release always has one.
BARE_VERSION := $(patsubst v%,%,$(VERSION))
PKG_VERSION := $(if $(shell echo '$(BARE_VERSION)' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+'),$(BARE_VERSION),0.0.0)

# The date in the man page header. Taken from the commit so two builds of the
# same tree produce the same page.
MAN_DATE ?= $(shell git log -1 --format=%cs 2>/dev/null || date -u +'%Y-%m-%d')

# Where a release is staged: the binaries the archives and the packages both
# read, and the man page. Only finished artefacts reach dist.
BUILD := build

.PHONY: all build install test race js lint lint-docker vuln check live fuzz goldens dist man \
	archives packages formula checksums image image-push image-web image-web-push web-lambda clean roothints demos demo-3d

# The stages of dist read each other's output, so they run one after another
# rather than at the same time.
.NOTPARALLEL:

all: check

build:
	$(GO) build -ldflags '$(LDFLAGS)' ./...

install:
	$(GO) install -ldflags '$(LDFLAGS)' ./cmd/dnstree

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

# The pages' own logic, under node's built-in test runner: nothing is
# installed, and nothing but node is needed.
js:
	$(NODE) --test 'internal/render/web/jstest/*.test.mjs'

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

check: build lint race js vuln

# Goes out to the real root servers, so it is never part of check.
live:
	$(GO) test -tags live -count=1 ./...

# Searches with every fuzz test for FUZZTIME, one at a time, since go test
# fuzzes one target of one package per run. check already replays their seeds
# and what earlier searches found, kept under testdata/fuzz. FUZZPKG narrows the
# search to the directories it names, as in FUZZPKG=internal/spf.
FUZZTIME ?= 30s
FUZZPKG ?= internal cmd
fuzz:
	@for file in $$(grep -rlE '^func Fuzz' --include='*_test.go' $(FUZZPKG) | sort); do \
		for name in $$(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/p' $$file); do \
			echo "$$name in ./$$(dirname $$file)"; \
			$(GO) test -run '^$$' -fuzz "^$$name$$" -fuzztime $(FUZZTIME) ./$$(dirname $$file) || exit 1; \
		done; \
	done

# Rewrites the renderer goldens, and docs/trace.schema.json with them. go test
# refuses a flag a package does not define, and only the packages that use
# internal/testutil/golden define -update, so those are the ones asked. One at
# a time and in order, since the markdown golden is drawn from the json one.
goldens:
	$(GO) test -p 1 $$(grep -lE 'golden\.(Compare|Updating)' internal/render/*/*_test.go | \
		xargs -n1 dirname | sort -u | sed 's|^|./|') -update

# dist builds a whole release: an archive per platform, a native package per
# Linux architecture, the Homebrew formula, and the checksums over all of them.
dist: clean man archives packages formula checksums

# The man page is rendered from the usage the binary itself prints, so a flag
# cannot reach one without reaching the other. gzip -n leaves the name and the
# timestamp out of the header, which keeps two builds of a tree identical.
man:
	@mkdir -p $(BUILD)
	@$(GO) run ./cmd/mkman -version '$(VERSION)' -date '$(MAN_DATE)' -output $(BUILD)/dnstree.1
	@gzip -9nc $(BUILD)/dnstree.1 > $(BUILD)/dnstree.1.gz

# archives cross compiles and archives each build. The binaries stay in
# $(BUILD) afterwards, because the packages are cut from the same ones.
archives:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=dnstree; [ "$$os" = windows ] && name=dnstree.exe; \
		echo "building $$os/$$arch"; \
		mkdir -p $(BUILD)/$${os}_$${arch}; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			$(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(BUILD)/$${os}_$${arch}/$$name ./cmd/dnstree || exit 1; \
		cp dnstreerc.example $(BUILD)/$${os}_$${arch}/; \
		if [ "$$os" = windows ]; then \
			(cd $(BUILD)/$${os}_$${arch} && \
				zip -q $(CURDIR)/dist/dnstree_$(VERSION)_$${os}_$${arch}.zip \
					$$name dnstreerc.example); \
		else \
			cp $(BUILD)/dnstree.1 $(BUILD)/$${os}_$${arch}/; \
			(cd $(BUILD)/$${os}_$${arch} && \
				tar czf $(CURDIR)/dist/dnstree_$(VERSION)_$${os}_$${arch}.tar.gz \
					$$name dnstree.1 dnstreerc.example); \
		fi; \
	done

# One nfpm run per architecture and format, all reading packaging/nfpm.yaml.
# nfpm does not expand an environment variable inside a path it globs, so the
# architecture being packaged is staged where the config expects it.
packages:
	@mkdir -p dist $(BUILD)/pkg
	@for entry in $(PKG_ARCHES); do \
		goarch=$${entry%:*}; pkgarch=$${entry#*:}; \
		cp $(BUILD)/linux_$$goarch/dnstree $(BUILD)/pkg/dnstree; \
		for format in $(PKG_FORMATS); do \
			echo "packaging $$format for $$pkgarch"; \
			PKG_ARCH=$$pkgarch PKG_VERSION=$(PKG_VERSION) \
				$(NFPM) package --config packaging/nfpm.yaml \
				--packager $$format --target dist/ >/dev/null || exit 1; \
		done; \
	done

# The Homebrew formula pours the archives built above, so it has to know their
# checksums and therefore comes after them.
formula:
	@./scripts/brew-formula.sh '$(VERSION)' dist > dist/dnstree.rb

checksums:
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

# The same two for dnstree-web, the page as a service, which a release
# publishes beside the command line's image.
image-web:
	docker buildx build \
		--target web \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg BUILD_VCS_REF=$(VCS_REF) \
		--build-arg BUILD_VERSION=$(VERSION) \
		--tag $(IMAGE)-web:$(VERSION) \
		--load \
		.

image-web-push:
	docker buildx build \
		--target web \
		--platform $(IMAGE_PLATFORMS) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg BUILD_VCS_REF=$(VCS_REF) \
		--build-arg BUILD_VERSION=$(VERSION) \
		--tag $(IMAGE)-web:$(VERSION) \
		--tag $(IMAGE)-web:latest \
		--push \
		.

# dnstree-web as a zip for Lambda's provided.al2023 runtime, one per
# architecture, to be uploaded by hand with the Lambda Web Adapter layer
# attached. Nothing publishes it.
web-lambda:
	@for arch in $(LAMBDA_ARCHES); do \
		dir=$(BUILD)/lambda_$$arch; \
		echo "building dnstree-web for lambda $$arch"; \
		rm -rf $$dir && mkdir -p $$dir; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 \
			$(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o $$dir/dnstree-web ./cmd/dnstree-web || exit 1; \
		install -m 755 packaging/lambda/bootstrap $$dir/bootstrap; \
		rm -f $(BUILD)/dnstree-web_$(VERSION)_lambda_$$arch.zip; \
		(cd $$dir && zip -qX $(CURDIR)/$(BUILD)/dnstree-web_$(VERSION)_lambda_$$arch.zip \
			bootstrap dnstree-web) || exit 1; \
	done
	@ls $(BUILD)/dnstree-web_$(VERSION)_lambda_*.zip

# Re-records the terminal demos in docs/ from tapes/, and the still of
# --format web-3d. Every one walks the real root servers, so the timings in a
# recording are whatever the recording machine's link gave that day, and two
# runs are never byte identical. Left out of check for that reason: it is run by
# hand when the output changes.
demos:
	@mkdir -p $(BUILD)
	@$(GO) build -ldflags '$(LDFLAGS)' -o $(BUILD)/dnstree ./cmd/dnstree
	@for tape in tapes/hero tapes/emoji tapes/dnssec tapes/bogus; do \
		echo "recording $$tape"; \
		PATH="$(CURDIR)/$(BUILD):$$PATH" $(VHS) $$tape.tape || exit 1; \
	done
	@DNSTREE=$(CURDIR)/$(BUILD)/dnstree ./scripts/demo-3d.sh

# Takes the still of --format web-3d in docs/ on its own. It needs Chrome or
# Chromium; CHROME names it when the script cannot find it.
demo-3d:
	@mkdir -p $(BUILD)
	@$(GO) build -ldflags '$(LDFLAGS)' -o $(BUILD)/dnstree ./cmd/dnstree
	@DNSTREE=$(CURDIR)/$(BUILD)/dnstree ./scripts/demo-3d.sh

# Refreshes the embedded root hints and trust anchors.
roothints:
	./scripts/refresh-roothints.sh

clean:
	rm -rf dist $(BUILD)
