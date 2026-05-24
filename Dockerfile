# ---- Frontend build ----
FROM node:26-alpine@sha256:7c6af15abe4e3de859690e7db171d0d711bf37d27528eddfe625b2fe89e097f8 AS frontend

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ---- Go build stage ----
FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /internal/server/webdist /src/internal/server/webdist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w \
    -X github.com/Infisical/agent-vault/cmd.version=${VERSION} \
    -X github.com/Infisical/agent-vault/cmd.commit=${COMMIT} \
    -X github.com/Infisical/agent-vault/cmd.date=${BUILD_DATE}" \
    -o /agent-vault .

# ---- Runtime stage ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

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
