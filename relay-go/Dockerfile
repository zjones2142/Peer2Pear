# Build stage — produces a statically linked binary
FROM golang:1.22-alpine AS build
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

# CGO is required for go-sqlite3. Static link everything.
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags='-s -w -extldflags "-static"' \
    -tags 'sqlite_omit_load_extension netgo osusergo' \
    -o /peer2pear-relay .

# Runtime stage — distroless (scratch + wget for healthcheck only).
# Using busybox as the base to get wget; still a minimal image.
FROM busybox:1.36

COPY --from=build /peer2pear-relay /peer2pear-relay
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV DB_PATH=/data/peer2pear_relay.db
VOLUME /data
EXPOSE 8443

# Parity fix: container-level health probe using the /healthz endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --spider -q http://127.0.0.1:8443/healthz || exit 1

ENTRYPOINT ["/peer2pear-relay"]
CMD ["--port", "8443"]
