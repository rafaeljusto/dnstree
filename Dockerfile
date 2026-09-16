# syntax=docker/dockerfile:1

# The builder runs on whatever the host is and cross compiles for the target,
# so an arm64 image is never built under emulation. Nothing from this stage
# reaches the image below except the binary itself.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src

# The dependencies change far less often than the code does.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -ldflags "-s -w -X main.version=$BUILD_VERSION" -o /out/dnstree ./cmd/dnstree

# The binary is static, so the image needs nothing but the root certificates
# the encrypted transports check a nameserver against. A distribution would
# only add packages this never calls, and their vulnerabilities with them.
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/dnstree /usr/local/bin/dnstree

# nonroot, by number: a name is only resolvable inside the image.
USER 65532:65532

ARG BUILD_DATE
ARG BUILD_VCS_REF
ARG BUILD_VERSION

LABEL org.opencontainers.image.title="dnstree" \
	org.opencontainers.image.description="Resolve a name from the root servers down, and draw the path it took" \
	org.opencontainers.image.source="https://github.com/rafaeljusto/dnstree" \
	org.opencontainers.image.url="https://github.com/rafaeljusto/dnstree" \
	org.opencontainers.image.licenses="MIT" \
	org.opencontainers.image.created=$BUILD_DATE \
	org.opencontainers.image.revision=$BUILD_VCS_REF \
	org.opencontainers.image.version=$BUILD_VERSION

ENTRYPOINT ["/usr/local/bin/dnstree"]
