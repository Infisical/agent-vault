# ---- Frontend build ----
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ---- Go build stage ----
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

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
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
