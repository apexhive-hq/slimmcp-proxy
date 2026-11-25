# `slimmcp-proxy` — Progressive-Disclosure Meta-MCP Proxy

[![slimmcp-proxy MCP server](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy/badge)](https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy)

> **Cut MCP context-window overhead by 97.87%** (`~15,047 -> ~320` tokens across 60 upstream tools) using deterministic BM25 tool discovery, lazy single-tool schema loading, local secret redaction, and pure Node.js `>=24`.

- **Interactive Browser Playground & Docs:** https://slimmcp-proxy-store.apexhive-hq.workers.dev
- **Agent Showcase & Calculator:** https://apexhive-showcase.pages.dev
- **Glama MCP Directory:** https://glama.ai/mcp/servers/apexhive-hq/slimmcp-proxy
- **Packages:** [`cli/`](./cli/) (`Node >=24`, zero Docker / zero C++ addons) &bull; [`storefront/`](./storefront/) (Cloudflare Workers playground, `x402` API, and Ed25519 license issuer)

---

## Architecture Flow

```text
+-------------------------------------------------------------------+
|  AI Coding Client (Claude Desktop / Claude Code / Cursor / Cline) |
|  Sees ONLY 3 meta-tools (~320 tokens total, 1,279 UTF-8 bytes)    |
+---------------------------------+---------------------------------+
                                  |  stdio (JSON-RPC 2.0)
                                  v
+-------------------------------------------------------------------+
|  slimmcp-proxy (cli/src/server.ts)                                |
|  1. discover_tools(query, server?, limit?) -> Pure-TS BM25 index  |
|  2. inspect_tool_schema(server, tool)      -> Lazy 1-tool schema  |
|  3. invoke_tool(server, tool, arguments)   -> Redactor + Policy   |
|     - Secret Redactor (AWS/GitHub/Stripe/OpenAI/Slack/JWT/PEM)    |
|     - PolicyGuard (optional RBAC + session/x402 spend caps)       |
|     - MetricsLedger (Node v24 built-in node:sqlite)               |
+---------------------------------+---------------------------------+
                                  |  stdio (spawns configured MCPs)
                                  v
+-------------------------------------------------------------------+
|  Upstream MCP Servers (e.g., 3 servers / 60 tools / ~15,047 tok)  |
+-------------------------------------------------------------------+
```

---

## Verified Local Benchmark

Measured with `node dist/src/cli.js benchmark --config slimmcp.config.example.json` against 3 real `stdio` child MCP servers (`60` tools total):

| Metric | Raw Upstream `tools/list` | `slimmcp-proxy` Meta-Tools | Reduction |
|---|---|---|---|
| **Exposed Tools** | `60` tools | `3` meta-tools | `95.0%` fewer tool definitions |
| **Serialized Payload** | `60,185` bytes | `1,279` bytes | **`97.87%` byte reduction** |
| **Heuristic Tokens (`~4 B/tok`)** | `~15,047` tokens | `~320` tokens | **`14,727` tokens saved/turn** |
| **1-Turn Lookup Cost** | `~15,047` tokens | `~735` tokens (meta + 5 matches + 1 schema) | **`95.1%` net turn savings** |

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

# Run unit & stdio integration tests (5/5 passing)
pnpm test
```

### Claude Desktop / Cursor `mcp.json` Configuration

```json
{
  "mcpServers": {
    "slimmcp": {
      "command": "npx",
      "args": [
        "-y",
        "slimmcp-proxy",
        "serve",
        "--config",
        "/abs/path/to/mcp-servers.json"
      ]
    }
  }
}
```

*(Accepts both `{ "servers": [...] }` and standard `{ "mcpServers": { ... } }` config files.)*

---

## Security, Policy Guardrails & Live Sandbox

- **Secret Redaction (Default On):** Automatically masks AWS keys, GitHub tokens, Stripe keys, OpenAI tokens, Slack tokens, JWTs, and PEM private keys before responses return to the LLM.
- **Policy-as-Code (`--policy slimmcp.policy.json`):** Enforce glob `allow`/`deny` tool rules, per-tool call budgets, and session `x402` USDC caps locally.
- **SQLite Telemetry (`node:sqlite`):** Inspect cumulative bytes/tokens saved and proxy latency via `node dist/src/cli.js stats --json`.
- **Browser Playground & Agent `x402` API:** Paste any MCP `tools/list` JSON at `https://slimmcp-proxy-store.apexhive-hq.workers.dev/#playground` or call `POST /api/playground/compress` (or `POST /api/x402/compress` for `x402` automated agents).

---

## License & Commercial Support

MIT Open Source (`$0`). Managed commercial multi-seat policy bundles, optional community sponsorship, and offline Ed25519 license tokens are available on the [ApexHive Labs Storefront](https://slimmcp-proxy-store.apexhive-hq.workers.dev). Support: `apexhive.hq@proton.me`.
