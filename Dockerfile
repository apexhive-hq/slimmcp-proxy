FROM node:24-slim

LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/apexhive-hq/slimmcp-proxy"

WORKDIR /app

RUN corepack enable

COPY cli/package.json cli/pnpm-lock.yaml cli/tsconfig.json cli/slimmcp.config.example.json ./
COPY cli/src ./src
COPY cli/tests ./tests

RUN pnpm install --frozen-lockfile --ignore-scripts && pnpm run build

ENV HOME=/tmp
ENV SLIMMCP_HOME=/tmp/slimmcp

RUN mkdir -p /tmp/slimmcp && chown -R node:node /app /tmp/slimmcp
USER node

ENTRYPOINT ["node", "dist/src/cli.js", "serve", "--config", "slimmcp.config.example.json", "--home", "/tmp/slimmcp", "--db", "/tmp/slimmcp/metrics.sqlite"]
