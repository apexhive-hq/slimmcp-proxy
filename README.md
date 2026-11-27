# `slimmcp-proxy` (`v1.0.3`) — Progressive-Disclosure Meta-MCP Proxy

[![slimmcp-proxy MCP server](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy/badge)](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy)

> Stop AI agents from burning context tokens loading dozens of unused MCP tool schemas. `slimmcp-proxy` sits in front of your `stdio`, Streamable-HTTP, and SSE MCP servers and exposes just **3 lightweight meta-tools** for BM25 tool discovery, lazy single-tool schema inspection, fail-closed secret redaction, and local RBAC policy enforcement.

- **Key Capabilities:**
  - **Progressive Tool Disclosure:** Exposes `discover_tools`, `inspect_tool_schema`, and `invoke_tool` instead of dumping every upstream tool definition upfront (`97.86%` initial schema reduction across 60 tools; `95.10%` net 1-turn savings).
  - **Multi-Transport Upstreams:** Proxies local `stdio` servers (with strict minimal environment isolation) and remote Streamable-HTTP / SSE servers (with metadata/SSRF and redirect guards).
  - **Security & Guardrails:** Fail-closed secret redaction (`depth <= 24`, keys + values), linear-time deny-overrides RBAC rules, per-tool call budgets, and built-in `node:sqlite` metrics (`Node.js >= 22.13.0`).
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
|  slimmcp-proxy v1.0.3 (cli/src/server.ts & upstream.ts)           |
|  1. discover_tools(query, server?, limit?) -> Pure-TS BM25 index  |
|  2. inspect_tool_schema(server, tool)      -> Lazy 1-tool schema  |
|  3. invoke_tool(server, tool, arguments)   -> Redactor + Policy   |
|     - Fail-Closed Secret Redactor (keys + values, depth <= 24)    |
|     - PolicyGuard (MIT RBAC deny-overrides + call/spend caps)     |
|     - MetricsLedger (Node >=22.13 built-in node:sqlite)           |
+---------------------------------+---------------------------------+
                                  |  stdio (isolated env) OR HTTP/SSE
                                  v
+-------------------------------------------------------------------+
|  Upstream MCP Servers (local processes or remote HTTP/SSE URLs)   |
+-------------------------------------------------------------------+
```

---

## Verified Local Benchmark (Initial Schema vs Multi-Turn Net Savings)

Measured with `pnpm run benchmark` (`node dist/src/cli.js benchmark --config slimmcp.benchmark.config.json`) against 3 real `stdio` child MCP servers (`60` tools total; heuristic `~4` UTF-8 bytes/token alongside exact UTF-8 byte counts):

| Metric | Raw Upstream `tools/list` | `slimmcp-proxy` Meta-Tools | Reduction / Net Cost |
|---|---|---|---|
| **Exposed Tools** | `60` tools | `3` meta-tools | `95.0%` fewer exposed definitions |
| **Initial `tools/list` Payload** | `60,185` bytes (`~15,047` tok) | `1,286` bytes (`~322` tok) | **`97.86%` initial schema reduction** (`14,725` tokens saved) |
| **Net 1-Turn Lookup Cost** *(meta + 5 BM25 matches + 1 inspected schema)* | `~15,047` tokens | **`~737` tokens** (`322 + 232 + 183`) | **`95.10%` net 1-turn savings** (`14,310` net tokens saved) |

### How Initial vs Multi-Turn Net Savings Work

- **Initial schema reduction (`97.86%`):** Instead of injecting all `60` upstream schemas (`60,185` bytes / `~15,047` tokens) into the prompt on turn 0, the client only loads the `3` meta-tools (`1,286` bytes / `~322` tokens).
- **1-turn net savings (`95.10%`):** Discovering and invoking a tool adds one `discover_tools` match list (`927` bytes / `~232` tokens for 5 matches) and one `inspect_tool_schema` payload (`~183` tokens), totaling `~737` tokens instead of `~15,047` tokens.
- **Multi-turn net savings:** Across a multi-turn session where only `k` distinct tools are actually needed (`k << 60`), each newly inspected tool adds only its single schema (`~183` tokens) rather than paying the full `~15,047`-token upfront schema tax across every conversation or prompt-cache miss.

---

## Quickstart (`Node.js >= 22.13.0`, Node 22 LTS / Node 24 LTS)

> **Why `>= 22.13.0`?** `slimmcp-proxy` uses Node's built-in unflagged `node:sqlite` (`DatabaseSync`, unflagged since Node 22.13.0) with zero native C++ addons. Node 20 LTS does not include `node:sqlite`.

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
pnpm run benchmark

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
      "args": ["/path/to/local-mcp.js"],
      "envAllowlist": ["CUSTOM_SAFE_VAR"],
      "connectTimeoutMs": 15000,
      "requestTimeoutMs": 30000
    },
    {
      "id": "remote-docs",
      "transport": "streamable-http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_MCP_TOKEN" }
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

## Security & Telemetry Features

- **Fail-Closed Secret Redaction (Default On):** Masks AWS keys, GitHub/GitLab/npm/HuggingFace/GCP/Stripe/OpenAI/Slack tokens, JWTs, Bearer headers, URL credentials, PEM private keys, hex keys, mnemonic seed phrases, and sensitive JSON object keys (`secret`, `token`, `password`, `apiKey`, `privateKey`, `mnemonic`, `authorization`, `cookie`, `credential`) — failing closed at `depth > 24` with `[REDACTED:MAX_DEPTH_EXCEEDED]`.
- **Policy-as-Code (`--policy slimmcp.policy.json`):** Linear-time glob `allow`/`deny` tool rules with strict **deny-overrides** precedence, per-tool call budgets, and session `x402` USDC spend caps enforced locally.
- **Child Process Env Isolation & Timeouts:** `stdio` upstreams receive only a minimal safe environment allowlist (`PATH`, `HOME`, `USERPROFILE`, `SYSTEMROOT`, `COMSPEC`, `TMP`, `TEMP`, `LANG`, `NODE_ENV`) plus explicit `env`/`envAllowlist` — host CI secrets like `GITHUB_TOKEN` or `NPM_TOKEN` are never blindly inherited. Configurable `connectTimeoutMs` and `requestTimeoutMs` ensure hung upstreams fail cleanly.
- **SQLite Telemetry (`node:sqlite`):** Inspect cumulative bytes/tokens saved and proxy latency via `node dist/src/cli.js stats --json`.

---

License: [MIT](LICENSE) · Support: `apexhive.hq@proton.me`.
