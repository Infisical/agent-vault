FROM --platform=linux/amd64 node:22-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM --platform=linux/amd64 node:22-slim
COPY --from=infisical/agent-vault:latest /usr/local/bin/agent-vault /usr/local/bin/agent-vault
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --omit=dev
COPY --from=builder /app/dist ./dist
# Workaround for anthropics/claude-agent-sdk-typescript#296: SDK resolver
# picks the musl native binary on glibc Linux and fails to spawn it.
# Pin to the glibc binary explicitly. Read by run-agent.ts.
ENV CLAUDE_CODE_EXECUTABLE=/app/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude
RUN test -x "$CLAUDE_CODE_EXECUTABLE"
# claude binary refuses --permission-mode bypassPermissions under root, so run
# as the unprivileged `node` user that ships with the base image.
RUN chown -R node:node /app
USER node
CMD ["agent-vault", "run", "--", "node", "dist/slack.js"]
