# `slimmcp-proxy` CLI (`v1.0.2`)

> **100% Free MIT Meta-MCP Proxy (`Node.js >= 22.13.0`, Node 22/24 LTS)**: reduces initial `tools/list` schemas by `97.86%` (`60,185 -> 1,286` bytes / `15,047 -> 322` tokens across 60 tools) and **net 1-turn lookup overhead by `95.10%` (`~15,047 -> ~737` tokens)** across both `stdio` and remote **Streamable-HTTP / SSE** upstream MCP servers.

---

## Quickstart (`Node.js >= 22.13.0`)

### Instant Run via npm (`npx`)

```bash
npx -y slimmcp-proxy --help
npx -y slimmcp-proxy serve --config /abs/path/to/mcp-servers.json
```

### Build from Source

```bash
git clone https://github.com/apexhive-hq/slimmcp-proxy.git
cd slimmcp-proxy/cli
pnpm install --ignore-scripts
pnpm run build

# Measure initial & 1-turn context savings on the 60-tool real stdio fixture
pnpm run benchmark

# Serve over stdio with optional free MIT RBAC & spend-cap guardrails
node dist/src/cli.js serve --config slimmcp.benchmark.config.json --policy slimmcp.policy.example.json
```

---

License: MIT · Support: `apexhive.hq@proton.me`.
