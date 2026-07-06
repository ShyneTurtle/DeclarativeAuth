# Stage 1: build a static binary
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/declarativeauth ./cmd/declarativeauth
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
