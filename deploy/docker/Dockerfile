# Stage 1: build a static binary
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/declarativeauth ./cmd/declarativeauth

# Stage 2: minimal runtime
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/declarativeauth /declarativeauth
USER nonroot:nonroot
ENTRYPOINT ["/declarativeauth"]
CMD ["serve"]
