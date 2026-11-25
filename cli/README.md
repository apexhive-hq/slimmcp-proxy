# `slimmcp-proxy` CLI

> **Cut MCP Context-Window Tax by up to 97.87%** using deterministic BM25 progressive tool discovery, lazy single-tool schema loading, and local secret redaction on Node.js `>=24`.

---

## Why `slimmcp-proxy`?

Connecting 3–10 Model Context Protocol (MCP) servers directly to Claude Desktop, Claude Code, Cursor, or Cline injects tens of thousands of tokens of raw JSON tool schemas into **every turn** before you type a word.

`slimmcp-proxy` sits transparently in front of your upstream `stdio` MCP servers and exposes only **3 lightweight meta-tools**:

1. **`discover_tools(query, server?, limit?)`** — Deterministic BM25 search returning compact tool summaries and required argument names.
2. **`inspect_tool_schema(server, tool)`** — Lazy-loads the exact JSON schema for the **single** tool you intend to invoke.
3. **`invoke_tool(server, tool, arguments)`** — Redacts leaked secrets (`AKIA...`, `ghp_...`, `sk-...`, PEM keys, JWTs), checks optional policy guardrails, and proxies execution cleanly.

Zero Docker, zero native C++ addons (`node-gyp`), zero external embeddings — runs on **Node.js `>=24.0.0`** using built-in **`node:sqlite`** and **`node:crypto`**.

---

## Quickstart

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

# Measure exact context savings on the 60-tool real stdio fixture
node dist/src/cli.js benchmark --config slimmcp.config.example.json

# Serve over stdio for Claude Desktop / Cursor / Cline
node dist/src/cli.js serve --config slimmcp.config.example.json
```

### Claude Desktop / Cursor `mcp.json` Snippet

```json
{
  "mcpServers": {
    "slimmcp": {
      "command": "npx",
      "args": ["-y", "slimmcp-proxy", "serve", "--config", "/path/to/mcp-servers.json"]
    }
  }
}
```

---

## Measured Benchmark Methodology

Running `node dist/src/cli.js benchmark --config slimmcp.config.example.json` connects to real `stdio` child MCP servers (`60` tools across `3` servers) and measures:

- **Raw Upstream `tools/list` Payload:** `60,185` UTF-8 bytes (`~15,047` heuristic tokens at `~4 B/tok`).
- **Slim Proxy `tools/list` Payload:** `1,279` UTF-8 bytes (`~320` tokens) for the 3 exposed meta-tools.
- **Measured Reduction:** **`97.87%` initial context reduction** (`14,727` tokens saved/turn).

---

## Policy Guardrails & SQLite Telemetry

Optionally attach `slimmcp.policy.json` and offline-verifiable Ed25519 licenses to enable glob `allow`/`deny` RBAC rules, per-tool call caps, session `x402` USDC spend caps, and `node:sqlite` metrics (`node dist/src/cli.js stats --json`):

```bash
node dist/src/cli.js activate --token "APEXHIVE-PRO-v1.<payload>.<signature>"
node dist/src/cli.js status
node dist/src/cli.js serve --config mcp.json --policy slimmcp.policy.json
```

---

## License & Commercial Support

MIT Open Source (`$0`). Managed multi-seat policy bundles, community sponsorship, and offline Ed25519 license activation are available on the [ApexHive Labs Storefront](https://slimmcp-proxy-store.apexhive-hq.workers.dev). Support: `apexhive.hq@proton.me`.
