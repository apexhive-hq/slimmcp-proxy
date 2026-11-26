FROM node:22-slim AS builder

WORKDIR /build

RUN corepack enable

COPY cli/package.json cli/pnpm-lock.yaml cli/tsconfig.json cli/tsconfig.build.json ./
COPY cli/src ./src

RUN pnpm install --frozen-lockfile --ignore-scripts \
  && pnpm run build:prod \
  && pnpm prune --prod --ignore-scripts

FROM node:22-slim AS runtime

LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/apexhive-hq/slimmcp-proxy"

WORKDIR /app

ENV NODE_ENV=production
ENV HOME=/tmp
ENV SLIMMCP_HOME=/tmp/slimmcp

COPY --from=builder /build/package.json ./
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY cli/slimmcp.policy.example.json README.md LICENSE ./

RUN mkdir -p /tmp/slimmcp && chown -R node:node /app /tmp/slimmcp
USER node

ENTRYPOINT ["node", "dist/src/cli.js"]
CMD ["--help"]
