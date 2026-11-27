# `slimmcp-proxy` CLI (`v1.0.3`)

> Stop AI agents from burning context tokens loading dozens of unused MCP tool schemas. `slimmcp-proxy` exposes 3 lightweight meta-tools for BM25 discovery, lazy schema lookup, secret redaction, and RBAC across `stdio` and remote Streamable-HTTP / SSE upstream MCP servers (`Node.js >= 22.13.0`, Node 22/24 LTS).
>
> Benchmark (60 tools): `97.86%` initial `tools/list` schema reduction (`60,185 -> 1,286` bytes / `15,047 -> 322` tokens) and `95.10%` net 1-turn savings (`~15,047 -> ~737` tokens).

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

# Serve over stdio with optional RBAC & spend-cap guardrails
node dist/src/cli.js serve --config slimmcp.benchmark.config.json --policy slimmcp.policy.example.json
```

---

License: MIT · Support: `apexhive.hq@proton.me`.
