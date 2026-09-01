# Stage 1: build a static binary
#
# --platform=$BUILDPLATFORM pins this stage to the *builder's* native arch
# regardless of which arch we're targeting, so cross-compiling for arm64
# from an amd64 CI runner (or vice versa) runs the Go toolchain natively --
# no QEMU emulation of the compiler itself, just Go's own GOOS/GOARCH
# cross-compilation. TARGETOS/TARGETARCH are set automatically by
# buildx per --platform entry (see .github/workflows/docker-build.yaml).
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION defaults to "dev" for local/untagged builds; CI passes the git tag
# or short SHA via --build-arg (see .github/workflows/docker-build.yaml).
# Baked in with -X rather than read at runtime so `declarativeauth serve`'s
# startup log and the admin/web UI's console.info both show a real build
# identifier with zero runtime config needed.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X declarativeauth/internal/buildinfo.Version=${VERSION}" \
    -o /out/declarativeauth ./cmd/declarativeauth
# Pre-create the identity mountpoint here, where a shell exists, so it
# lands in the final image with known-good permissions (0755: traversable
# by the "nonroot" user the final stage runs as). The distroless base below
# has no /etc/declarativeauth of its own -- if left for Docker to
# auto-create at `docker run`/compose time (because a volume is mounted
# under it but the directory doesn't already exist in the image), some
# Docker versions/storage drivers create missing bind-mount parents as
# root-only, silently blocking the non-root container process from reading
# anything mounted there. So we need to pre-create it here in the build stage, 
# where we can set the permissions correctly, and then copy it into the final image.
RUN mkdir -p /identity && chmod 755 /identity

# Stage 2: minimal runtime
#
# No --platform here: a stage with no explicit --platform already defaults
# to $TARGETPLATFORM, so this pulls the arm64 or amd64 variant of the
# distroless base to match whichever platform this image instance is
# actually for. No RUN steps below, only COPY, so no emulation is needed
# for this stage either.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/declarativeauth /declarativeauth
COPY --from=build /identity /etc/declarativeauth/identity
USER nonroot:nonroot
ENTRYPOINT ["/declarativeauth"]
CMD ["serve"]
# Distroless has no shell/curl/wget, so the healthcheck is the binary
# itself (see cmd/declarativeauth/cmd_healthcheck.go) hitting its own
# /readyz over loopback -- a real readiness check (Postgres included), not
# just "process is alive". Only meaningful for the "serve" CMD; harmless
# no-op relevance for other one-shot subcommands since nothing orchestrates
# healthchecks for those.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/declarativeauth", "healthcheck"]
