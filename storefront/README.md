# `slimmcp-proxy` Edge Playground, `x402` API & Storefront

Cloudflare Workers + Workers KV application powering:

1. **Free Browser Playground (`POST /api/playground/compress`):** Zero-install MCP `tools/list` JSON schema compressor and token-savings analyzer.
2. **Agent `x402` Micro-Pay API (`POST /api/x402/compress`):** Pay-per-call Base USDC (`eip155:8453`) compression endpoint (`$0.005 USDC` / `5000` atomic units authenticated via `X-Payment`, `X-Payment-Signature`, and `X-Payment-Address`).
3. **Non-Custodial License Issuer:** Verifies Base Mainnet USDC transfers (`0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`), enforces EIP-191 ownership proofs, and issues offline-verifiable Ed25519 license tokens.

## Local Verification

```bash
pnpm run typecheck
pnpm test
```
