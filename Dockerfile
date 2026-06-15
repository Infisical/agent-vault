# ---- Frontend build ----
FROM node:26-alpine@sha256:3ad34ca6292aec4a91d8ddeb9229e29d9c2f689efd0dd242860889ac71842eba AS frontend

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ---- Go build stage ----
FROM golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG POSTHOG_API_KEY=

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /internal/server/webdist /src/internal/server/webdist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w \
    -X github.com/Infisical/agent-vault/cmd.version=${VERSION} \
    -X github.com/Infisical/agent-vault/cmd.commit=${COMMIT} \
    -X github.com/Infisical/agent-vault/cmd.date=${BUILD_DATE} \
    -X github.com/Infisical/agent-vault/cmd.posthogAPIKey=${POSTHOG_API_KEY}" \
    -o /agent-vault .

# ---- Runtime stage ----
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

RUN apk add --no-cache ca-certificates \
    && addgroup -S agentvault && adduser -S -G agentvault -u 65532 agentvault \
    && mkdir -p /data/.agent-vault && chown -R agentvault:agentvault /data

COPY --from=builder /agent-vault /usr/local/bin/agent-vault
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV HOME=/data
VOLUME /data
EXPOSE 14321
USER agentvault

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:14321/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["server", "--host", "0.0.0.0", "--port", "14321"]
