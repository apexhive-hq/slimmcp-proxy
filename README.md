# `slimmcp-proxy` — Progressive-Disclosure Meta-MCP Proxy

[![slimmcp-proxy MCP server](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy/badge)](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy)

> **100% Free & Open Source (MIT)** Meta-MCP proxy (`Node.js >= 24`) that replaces bloated upstream `tools/list` definitions with **3 lightweight meta-tools** (`97.86%` initial schema reduction: `60,185 -> 1,286` bytes across 60 tools; **`~95.1%` net 1-turn savings** including `discover_tools` + `inspect_tool_schema`), supporting **`stdio`**, **Streamable-HTTP**, and **SSE** upstreams with built-in secret redaction and free RBAC policy guardrails.

- **Official MCP Registry:** `io.github.apexhive-hq/slimmcp-proxy`
- **Glama MCP Directory:** https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy

---

## Architecture Flow

```text
+-------------------------------------------------------------------+
|  AI Coding Client (Claude Desktop / Claude Code / Cursor / Cline) |
|  Sees ONLY 3 meta-tools (~322 tokens initial schema, 1,286 bytes) |
+---------------------------------+---------------------------------+
                                  |  stdio (JSON-RPC 2.0)
                                  v
+-------------------------------------------------------------------+
|  slimmcp-proxy (cli/src/server.ts & upstream.ts)                  |
|  1. discover_tools(query, server?, limit?) -> Pure-TS BM25 index  |
|  2. inspect_tool_schema(server, tool)      -> Lazy 1-tool schema  |
|  3. invoke_tool(server, tool, arguments)   -> Redactor + Policy   |
|     - Secret Redactor (AWS/GitHub/Stripe/OpenAI/Slack/JWT/PEM)    |
|     - PolicyGuard (100% Free MIT RBAC + call/spend caps)          |
|     - MetricsLedger (Node v24 built-in node:sqlite)               |
+---------------------------------+---------------------------------+
                                  |  stdio OR Streamable-HTTP / SSE
                                  v
+-------------------------------------------------------------------+
|  Upstream MCP Servers (local processes or remote HTTP/SSE URLs)   |
+-------------------------------------------------------------------+
```

---

## Verified Local Benchmark (Initial + 1-Turn Reality)

Measured with `node dist/src/cli.js benchmark --config slimmcp.config.example.json` against 3 real `stdio` child MCP servers (`60` tools total):

| Metric | Raw Upstream `tools/list` | `slimmcp-proxy` Meta-Tools | Reduction |
|---|---|---|---|
| **Exposed Tools** | `60` tools | `3` meta-tools | `95.0%` fewer exposed definitions |
| **Initial `tools/list` Payload** | `60,185` bytes (`~15,047` tok) | `1,286` bytes (`~322` tok) | **`97.86%` initial schema reduction** |
| **Net 1-Turn Lookup Cost** *(meta + 5 BM25 matches + 1 loaded schema)* | `~15,047` tokens | **`~737` tokens** | **`~95.1%` net 1-turn savings** |

---

## Quickstart (`Node.js >= 24.0.0`, Zero Docker)

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

# Run the 60-tool real stdio benchmark
node dist/src/cli.js benchmark --config slimmcp.config.example.json

# Run unit, stdio, and Streamable-HTTP integration tests
pnpm test
```

### Upstream Config (`stdio` + Streamable-HTTP / SSE)

Accepts both `{ "servers": [...] }` and standard `{ "mcpServers": { ... } }`:

```json
{
  "servers": [
    {
      "id": "filesystem",
      "command": "node",
      "args": ["/path/to/local-mcp.js"]
    },
    {
      "id": "remote-docs",
      "transport": "streamable-http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer ${MCP_TOKEN}" }
    }
  ]
}
```

### Claude Desktop / Cursor `mcp.json`

```json
{
  "mcpServers": {
    "slimmcp": {
      "command": "npx",
      "args": ["-y", "slimmcp-proxy", "serve", "--config", "/abs/path/to/mcp-servers.json"]
    }
  }
}
```

---

## Security & Telemetry Features (100% Free MIT)

- **Secret Redaction (Default On):** Automatically masks AWS keys, GitHub tokens, Stripe keys, OpenAI tokens, Slack tokens, JWTs, and PEM private keys before responses return to the LLM.
- **Policy-as-Code (`--policy slimmcp.policy.json`):** Enforce glob `allow`/`deny` tool rules, per-tool call budgets, and session `x402` USDC caps locally at no cost.
- **SQLite Telemetry (`node:sqlite`):** Inspect cumulative bytes/tokens saved and proxy latency via `node dist/src/cli.js stats --json`.

---

If `slimmcp-proxy` saved your context budget, Base USDC tips are welcome at `0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`. Support: `apexhive.hq@proton.me`.
