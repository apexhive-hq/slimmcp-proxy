# `slimmcp-proxy` CLI

> **100% Free MIT Meta-MCP Proxy (`Node.js >= 24`)**: reduces initial `tools/list` schemas by `97.86%` (`60,185 -> 1,286` bytes across 60 tools) and **net 1-turn lookup overhead by `~95.1%` (`~15,047 -> ~737` tokens)** across both `stdio` and remote **Streamable-HTTP / SSE** upstream MCP servers.

---

## Quickstart (`Node.js >= 24.0.0`)

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
node dist/src/cli.js benchmark --config slimmcp.config.example.json

# Serve over stdio with optional free MIT RBAC & spend-cap guardrails
node dist/src/cli.js serve --config slimmcp.config.example.json --policy slimmcp.policy.example.json
```

---

Tips (Base USDC): `0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206` · Support: `apexhive.hq@proton.me`.
