import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyMessage } from 'viem';

export interface Env {
  ASSETS: Fetcher;
  LICENSES_KV: KVNamespace;
  GLOBAL_CLAIMED_TX_KV: KVNamespace;
  BRAND_NAME: string;
  PRODUCT_ID: string;
  PAY_TO_EVM_ADDRESS: string;
  BASE_USDC_CONTRACT: string;
  BASE_CHAIN_ID: string;
  BASE_RPC_URL: string;
  BASE_RPC_URLS?: string;
  PRO_PRICE_USDC_ATOMIC: string;
  TEAM_PRICE_USDC_ATOMIC: string;
  MIN_CONFIRMATIONS: string;
  SOLANA_RECEIVE_ADDRESS: string;
  BTC_RECEIVE_ADDRESS: string;
  TRON_RECEIVE_ADDRESS: string;
  LICENSE_SIGNING_PRIVATE_JWK?: string;
  LICENSE_SIGNING_PUBLIC_SPKI_B64?: string;
}

type Tier = 'indie' | 'team';

// ─── Batch ladder (Indie only; Team is lifetime fixed) ──────────────────────
interface Batch {
  name: string;
  atomicPrice: bigint;
  threshold: number;
}

const INDIE_BATCHES: Batch[] = [
  { name: 'Founding Batch', atomicPrice: 5_000_000n, threshold: 3 },
  { name: 'Early Batch', atomicPrice: 9_000_000n, threshold: 13 },
  { name: 'Growth Batch', atomicPrice: 15_000_000n, threshold: 113 },
  { name: 'Standard', atomicPrice: 19_000_000n, threshold: Infinity }
];
const GRACE_MS = 180_000;

function getActiveBatch(soldCount: number): Batch {
  for (const b of INDIE_BATCHES) {
    if (soldCount < b.threshold) return b;
  }
  return INDIE_BATCHES[INDIE_BATCHES.length - 1];
}

const ERC20_TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const SIG_RE = /^0x[0-9a-fA-F]{130}$/;
const STRICT_HEX_RE = /^0x[0-9a-fA-F]+$/;
const CHALLENGE_TTL_SECONDS = 300;
const TOKEN_PREFIX = 'APEXHIVE-PRO-v1.';
const SCOPE_STOREFRONT = 'storefront:slimmcp';
const SCOPE_X402 = 'x402:slimmcp';

interface ChallengeRecord {
  nonce: string;
  txHash: string;
  tier: Tier;
  ts: number;
  message: string;
  lockedAtomic: string;
}

interface GlobalClaimRecord {
  scope: string;
  payer: string;
  tier: string;
  txHash: string;
  claimedAt: number;
}

interface RpcLog {
  address: string;
  topics: string[];
  data: string;
}

interface RpcReceipt {
  status: string;
  blockNumber: string;
  logs: RpcLog[];
}

interface BatchGrace {
  prevAtomic: string;
  graceUntilMs: number;
}

function parseStrictHexBigInt(val: unknown): bigint | null {
  if (typeof val !== 'string' || !STRICT_HEX_RE.test(val)) return null;
  return BigInt(val);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function normalizeAddressFromTopic(topic: string): string {
  return `0x${topic.slice(-40).toLowerCase()}`;
}

function buildChallengeMessage(params: {
  brand: string;
  product: string;
  tier: Tier;
  txHash: string;
  nonce: string;
  ts: number;
}): string {
  return [
    `${params.brand} License Ownership Proof`,
    `product=${params.product}`,
    `tier=${params.tier}`,
    `tx=${params.txHash.toLowerCase()}`,
    `nonce=${params.nonce}`,
    `ts=${params.ts}`
  ].join('\n');
}

const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

function getBaseRpcUrls(env: Env): string[] {
  if (env.BASE_RPC_URLS && env.BASE_RPC_URLS.trim()) {
    const parsed = env.BASE_RPC_URLS.split(',')
      .map((u) => u.trim())
      .filter(Boolean);
    if (parsed.length > 0) return parsed;
  }
  if (env.BASE_RPC_URL && env.BASE_RPC_URL.trim()) {
    return [env.BASE_RPC_URL.trim()];
  }
  return DEFAULT_BASE_RPC_URLS;
}

async function rpcCallSingle<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(6000)
  });
  if (!res.ok) {
    throw new Error(`RPC HTTP ${res.status}`);
  }
  const json = (await res.json()) as { result?: T; error?: { message?: string } };
  if (json.error) {
    throw new Error(`RPC error: ${json.error.message ?? 'unknown'}`);
  }
  return json.result as T;
}

async function rpcCallWithFailover<T>(
  urls: string[],
  method: string,
  params: unknown[]
): Promise<T> {
  let lastError: unknown;
  for (const url of urls) {
    try {
      return await rpcCallSingle<T>(url, method, params);
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(
    `All Base RPC endpoints failed: ${lastError instanceof Error ? lastError.message : 'unknown'}`
  );
}

async function signLicenseToken(
  env: Env,
  payload: {
    v: 1;
    product: 'slimmcp-proxy';
    tier: Tier;
    payer: string;
    txHash: string;
    issuedAt: number;
    expiresAt: null;
  }
): Promise<string> {
  if (!env.LICENSE_SIGNING_PRIVATE_JWK) {
    throw new Error('Server missing LICENSE_SIGNING_PRIVATE_JWK secret.');
  }
  const jwk = JSON.parse(env.LICENSE_SIGNING_PRIVATE_JWK) as JsonWebKey;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    false,
    ['sign']
  );

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const payloadB64Url = base64UrlEncode(payloadBytes);
  const signingInput = new TextEncoder().encode(`${TOKEN_PREFIX}${payloadB64Url}`);
  const sigBuf = await crypto.subtle.sign('Ed25519', key, signingInput);
  const sigB64Url = base64UrlEncode(new Uint8Array(sigBuf));

  return `${TOKEN_PREFIX}${payloadB64Url}.${sigB64Url}`;
}

const MAX_PLAYGROUND_BYTES = 262_144;
const MAX_PLAYGROUND_TOOLS = 500;
const MAX_JSON_DEPTH = 32;
const X402_PRICE_ATOMIC = 5000n;

const SLIM_META_TOOLS = [
  {
    name: 'discover_tools',
    description: 'BM25 search across connected MCP tools returning compact names and required args.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        server: { type: 'string' },
        limit: { type: 'number' }
      },
      required: ['query']
    }
  },
  {
    name: 'inspect_tool_schema',
    description: 'Lazy-load full inputSchema for a single discovered MCP tool.',
    inputSchema: {
      type: 'object',
      properties: { server: { type: 'string' }, tool: { type: 'string' } },
      required: ['server', 'tool']
    }
  },
  {
    name: 'invoke_tool',
    description: 'Invoke a discovered MCP tool with secret redaction and optional policy guardrails.',
    inputSchema: {
      type: 'object',
      properties: {
        server: { type: 'string' },
        tool: { type: 'string' },
        arguments: { type: 'object' }
      },
      required: ['server', 'tool']
    }
  }
];

function exceedsJsonDepth(text: string, maxDepth: number): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === 92) {
        escaped = true;
      } else if (ch === 34) {
        inString = false;
      }
      continue;
    }
    if (ch === 34) {
      inString = true;
    } else if (ch === 123 || ch === 91) {
      depth += 1;
      if (depth > maxDepth) return true;
    } else if (ch === 125 || ch === 93) {
      depth -= 1;
    }
  }
  return false;
}

function sumBaseUsdcTransfers(
  logs: RpcLog[] | undefined,
  expectedUsdcContract: string,
  expectedPayTo: string
): Map<string, bigint> {
  const expectedUsdc = expectedUsdcContract.toLowerCase();
  const expectedTo = expectedPayTo.toLowerCase();
  const payerTotals = new Map<string, bigint>();
  for (const log of logs ?? []) {
    if (log.address?.toLowerCase() !== expectedUsdc) continue;
    if (!log.topics || log.topics.length < 3) continue;
    if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC) continue;
    const from = normalizeAddressFromTopic(log.topics[1]);
    const to = normalizeAddressFromTopic(log.topics[2]);
    if (to !== expectedTo) continue;
    const value = parseStrictHexBigInt(log.data);
    if (value === null) continue;
    payerTotals.set(from, (payerTotals.get(from) ?? 0n) + value);
  }
  return payerTotals;
}

interface RawToolLike {
  name?: unknown;
  description?: unknown;
  inputSchema?: { required?: unknown };
}

function compressMcpToolsPayload(rawBodyText: string):
  | {
      ok: true;
      toolCount: number;
      rawBytes: number;
      compressedBytes: number;
      bytesSaved: number;
      rawTokensEst: number;
      compressedTokensEst: number;
      tokensSaved: number;
      reductionPct: number;
      metaTools: typeof SLIM_META_TOOLS;
      indexedTools: Array<{ name: string; summary: string; requiredArgs: string[] }>;
    }
  | { ok: false; status: 400 | 413; error: string; message: string } {
  const utf8Encoder = new TextEncoder();
  const rawBodyBytes = utf8Encoder.encode(rawBodyText).length;
  if (rawBodyBytes > MAX_PLAYGROUND_BYTES) {
    return {
      ok: false,
      status: 413,
      error: 'PAYLOAD_TOO_LARGE',
      message: `Payload exceeds ${MAX_PLAYGROUND_BYTES} bytes limit.`
    };
  }
  if (exceedsJsonDepth(rawBodyText, MAX_JSON_DEPTH)) {
    return {
      ok: false,
      status: 400,
      error: 'NESTING_DEPTH_EXCEEDED',
      message: `JSON nesting exceeds ${MAX_JSON_DEPTH} levels.`
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBodyText);
  } catch {
    return { ok: false, status: 400, error: 'INVALID_JSON', message: 'Expected valid JSON payload.' };
  }

  let toolsRaw: unknown = null;
  if (Array.isArray(parsed)) {
    toolsRaw = parsed;
  } else if (parsed && typeof parsed === 'object') {
    const obj = parsed as { tools?: unknown; result?: { tools?: unknown } };
    if (Array.isArray(obj.tools)) {
      toolsRaw = obj.tools;
    } else if (obj.result && Array.isArray(obj.result.tools)) {
      toolsRaw = obj.result.tools;
    }
  }

  if (!Array.isArray(toolsRaw) || toolsRaw.length === 0) {
    return {
      ok: false,
      status: 400,
      error: 'INVALID_TOOLS_PAYLOAD',
      message: 'Provide a non-empty array or { tools: [...] } MCP tools/list JSON payload.'
    };
  }
  if (toolsRaw.length > MAX_PLAYGROUND_TOOLS) {
    return {
      ok: false,
      status: 413,
      error: 'TOO_MANY_TOOLS',
      message: `Maximum ${MAX_PLAYGROUND_TOOLS} tools allowed per call.`
    };
  }

  const tools = toolsRaw as RawToolLike[];
  for (const t of tools) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string' || !t.name.trim()) {
      return {
        ok: false,
        status: 400,
        error: 'INVALID_TOOL_ENTRY',
        message: 'Every tool entry must be an object with a non-empty string name.'
      };
    }
  }

  const rawBytes = utf8Encoder.encode(JSON.stringify({ tools })).length;
  const compressedBytes = utf8Encoder.encode(JSON.stringify({ tools: SLIM_META_TOOLS })).length;
  const rawTokensEst = Math.ceil(rawBytes / 4);
  const compressedTokensEst = Math.ceil(compressedBytes / 4);
  const bytesSaved = Math.max(0, rawBytes - compressedBytes);
  const tokensSaved = Math.max(0, rawTokensEst - compressedTokensEst);
  const reductionPct = Number(((bytesSaved / Math.max(1, rawBytes)) * 100).toFixed(2));

  const indexedTools = tools.map((t) => {
    const req = t.inputSchema && Array.isArray(t.inputSchema.required)
      ? t.inputSchema.required.filter((r): r is string => typeof r === 'string')
      : [];
    return {
      name: String(t.name).trim(),
      summary: typeof t.description === 'string' ? t.description.slice(0, 120) : '',
      requiredArgs: req
    };
  });

  return {
    ok: true,
    toolCount: tools.length,
    rawBytes,
    compressedBytes,
    bytesSaved,
    rawTokensEst,
    compressedTokensEst,
    tokensSaved,
    reductionPct,
    metaTools: SLIM_META_TOOLS,
    indexedTools
  };
}

// ─── App ─────────────────────────────────────────────────────────────────────
const app = new Hono<{ Bindings: Env }>();

const apiCors = cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: [
    'Content-Type',
    'X-Payment',
    'X-Payment-Signature',
    'X-Payment-Address',
    'X-ApexHive-License'
  ],
  exposeHeaders: ['X-Payment-Required']
});

app.use('/api/*', apiCors);
app.use('/.well-known/*', apiCors);
app.use('/openapi.json', apiCors);

app.use('*', async (c, next) => {
  await next();
  const ct = c.res.headers.get('content-type');
  if (ct && (ct.startsWith('application/json') || ct.startsWith('text/html')) && !/charset=/i.test(ct)) {
    c.res.headers.set('content-type', `${ct}; charset=utf-8`);
  }
});

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0b1020"/><path d="M9 11h14M9 16h10M9 21h6" stroke="#22d3ee" stroke-width="3" stroke-linecap="round"/></svg>`;

function buildX402PaymentRequiredV2(env: Env, origin: string) {
  const payTo = env.PAY_TO_EVM_ADDRESS;
  const asset = env.BASE_USDC_CONTRACT;
  const resourceUrl = `${origin}/api/x402/compress`;
  return {
    x402Version: 2,
    error: 'PAYMENT_REQUIRED',
    resource: {
      url: resourceUrl,
      description:
        'Compress and index MCP tools/list JSON schemas ($0.005 USDC on Base Mainnet; include X-Payment, X-Payment-Signature, X-Payment-Address)',
      mimeType: 'application/json'
    },
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        amount: X402_PRICE_ATOMIC.toString(),
        payTo,
        maxTimeoutSeconds: 300,
        asset,
        extra: {
          name: 'USD Coin',
          version: '2',
          signatureRequired: true,
          signatureHeaders: ['X-Payment', 'X-Payment-Signature', 'X-Payment-Address'],
          signatureMessageTemplate: 'ApexHive x402 slimmcp-compress\ntxHash:<txHash_lowercase>'
        }
      }
    ],
    extensions: {
      bazaar: {
        info: {
          input: {
            type: 'http',
            method: 'POST',
            bodyType: 'json',
            body: {
              tools: [
                {
                  name: 'search_docs',
                  description: 'Search workspace documentation',
                  inputSchema: {
                    type: 'object',
                    properties: { query: { type: 'string' } },
                    required: ['query']
                  }
                }
              ]
            }
          },
          output: {
            type: 'json',
            example: {
              ok: true,
              toolCount: 1,
              rawBytes: 182,
              compressedBytes: 798,
              reductionPct: 97.87,
              metaTools: SLIM_META_TOOLS,
              indexedTools: [
                {
                  name: 'search_docs',
                  summary: 'Search workspace documentation',
                  requiredArgs: ['query']
                }
              ]
            }
          }
        },
        schema: {
          $schema: 'https://json-schema.org/draft/2020-12/schema',
          type: 'object',
          required: ['input'],
          properties: {
            input: {
              type: 'object',
              required: ['type', 'method', 'bodyType', 'body'],
              properties: {
                type: { type: 'string', const: 'http' },
                method: { type: 'string', const: 'POST' },
                bodyType: { type: 'string', const: 'json' },
                body: {
                  type: 'object',
                  properties: {
                    tools: {
                      type: 'array',
                      maxItems: 500,
                      items: {
                        type: 'object',
                        required: ['name'],
                        properties: {
                          name: { type: 'string' },
                          description: { type: 'string' },
                          inputSchema: { type: 'object' }
                        }
                      }
                    },
                    mcpServers: { type: 'object' },
                    query: { type: 'string' },
                    limit: { type: 'number' }
                  }
                }
              }
            },
            output: {
              type: 'object',
              properties: {
                type: { type: 'string', const: 'json' },
                example: {
                  type: 'object',
                  properties: {
                    ok: { type: 'boolean' },
                    toolCount: { type: 'number' },
                    rawBytes: { type: 'number' },
                    compressedBytes: { type: 'number' },
                    reductionPct: { type: 'number' },
                    metaTools: { type: 'array' },
                    indexedTools: { type: 'array' }
                  }
                }
              }
            }
          }
        }
      }
    }
  };
}

app.get('/favicon.svg', () => {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=86400'
    }
  });
});

app.get('/favicon.ico', () => {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=86400'
    }
  });
});

app.get('/.well-known/x402', (c) => {
  const origin = new URL(c.req.url).origin;
  const v2 = buildX402PaymentRequiredV2(c.env, origin);
  return c.json({
    ...v2,
    name: 'slimmcp-proxy Edge Compression & x402 API',
    provider: c.env.BRAND_NAME || 'ApexHive Labs',
    contact: 'apexhive.hq@proton.me',
    homepage: origin,
    openapi: `${origin}/openapi.json`,
    freeEndpoints: [
      {
        method: 'POST',
        path: '/api/playground/compress',
        url: `${origin}/api/playground/compress`,
        description: 'Free in-browser MCP tools/list compressor (max 262,144 bytes / 500 tools).'
      }
    ]
  });
});

app.get('/openapi.json', (c) => {
  const origin = new URL(c.req.url).origin;
  const payTo = c.env.PAY_TO_EVM_ADDRESS;
  const usdc = c.env.BASE_USDC_CONTRACT;
  return c.json({
    openapi: '3.1.0',
    info: {
      title: 'slimmcp-proxy Edge Playground & x402 API',
      version: '1.0.1',
      description:
        'Compress bloated MCP tools/list JSON schemas into 3 progressive-disclosure meta-tools with exact UTF-8 byte & token metrics.',
      'x-guidance':
        "Use POST /api/playground/compress for free schema compression, or call POST /api/x402/compress for paid agent compression ($0.005 USDC = 5000 atomic units on Base Mainnet eip155:8453). Transfer >= 5000 atomic USDC to payTo and include X-Payment (txHash), X-Payment-Signature (EIP-191 over 'ApexHive x402 slimmcp-compress\\ntxHash:<txHash_lowercase>'), and X-Payment-Address headers.",
      contact: {
        name: 'ApexHive Labs',
        email: 'apexhive.hq@proton.me'
      }
    },
    servers: [{ url: origin }],
    paths: {
      '/api/playground/compress': {
        post: {
          summary: 'Free MCP tools/list compressor & token-savings analyzer',
          description: 'Accepts up to 262,144 bytes / 500 tools with zero setup or KV writes.',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tools'],
                  properties: {
                    tools: { type: 'array', maxItems: 500, items: { type: 'object' } }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Compressed meta-tool manifest and exact byte/token savings',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      ok: { type: 'boolean' },
                      toolCount: { type: 'number' },
                      rawBytes: { type: 'number' },
                      compressedBytes: { type: 'number' },
                      reductionPct: { type: 'number' },
                      metaTools: { type: 'array' },
                      indexedTools: { type: 'array' }
                    }
                  }
                }
              }
            },
            '400': { description: 'Invalid JSON, missing tools, or nesting depth exceeded' },
            '413': { description: 'Payload exceeds 262,144 bytes or 500 tools' }
          }
        }
      },
      '/api/x402/compress': {
        post: {
          summary: 'x402 Base USDC paid MCP tools/list compression ($0.005 USDC)',
          description: `Pay 5000 atomic Base USDC (${usdc}, eip155:8453) to ${payTo} and sign "ApexHive x402 slimmcp-compress\\ntxHash:<txHash_lowercase>" with EIP-191.`,
          'x-payment-info': {
            price: { mode: 'fixed', currency: 'USD', amount: '0.005' },
            protocols: [{ x402: {} }]
          },
          'x-x402': {
            x402Version: 2,
            scheme: 'exact',
            network: 'eip155:8453',
            asset: usdc,
            payTo,
            amount: X402_PRICE_ATOMIC.toString(),
            signatureRequired: true,
            signatureHeaders: ['X-Payment', 'X-Payment-Signature', 'X-Payment-Address'],
            signatureMessageTemplate: 'ApexHive x402 slimmcp-compress\ntxHash:<txHash_lowercase>'
          },
          parameters: [
            {
              name: 'X-Payment',
              in: 'header',
              required: true,
              description: '0x-prefixed 64-hex Base Mainnet transaction hash transferring >= 5000 atomic USDC.',
              schema: { type: 'string', pattern: '^0x[0-9a-fA-F]{64}$' }
            },
            {
              name: 'X-Payment-Signature',
              in: 'header',
              required: true,
              description: 'EIP-191 personal_sign signature over "ApexHive x402 slimmcp-compress\\ntxHash:<txHash_lowercase>".',
              schema: { type: 'string', pattern: '^0x[0-9a-fA-F]{130}$' }
            },
            {
              name: 'X-Payment-Address',
              in: 'header',
              required: true,
              description: '0x-prefixed EVM address of the Base USDC Transfer sender.',
              schema: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' }
            }
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tools'],
                  properties: {
                    tools: { type: 'array', maxItems: 500, items: { type: 'object' } }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Compressed meta-tool manifest and settled Base payment receipt',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      ok: { type: 'boolean' },
                      toolCount: { type: 'number' },
                      rawBytes: { type: 'number' },
                      compressedBytes: { type: 'number' },
                      reductionPct: { type: 'number' },
                      metaTools: { type: 'array' },
                      indexedTools: { type: 'array' },
                      payment: { type: 'object' }
                    }
                  }
                }
              }
            },
            '401': { description: 'Missing X-Payment-Signature or X-Payment-Address' },
            '402': { description: 'Payment Required' },
            '403': { description: 'Invalid signature, insufficient amount/confirmations, or txHash already claimed' },
            '413': { description: 'Payload exceeds 262,144 bytes or 500 tools' }
          }
        }
      },
      '/api/health': {
        get: {
          summary: 'Service health and KV binding status',
          security: [],
          responses: { '200': { description: 'OK' } }
        }
      },
      '/api/config': {
        get: {
          summary: 'Checkout configuration and active tier pricing',
          security: [],
          responses: { '200': { description: 'OK' } }
        }
      }
    }
  });
});

app.get('/api/health', async (c) => {
  const soldCountRaw = await c.env.LICENSES_KV.get('stats:sold_indie');
  const soldCount = soldCountRaw ? Number(soldCountRaw) : 0;
  const batch = getActiveBatch(soldCount);
  return c.json({
    ok: true,
    service: 'slimmcp-proxy-store',
    brand: c.env.BRAND_NAME,
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    kvBound: Boolean(c.env.LICENSES_KV),
    globalKvBound: Boolean(c.env.GLOBAL_CLAIMED_TX_KV),
    indiePriceAtomic: String(batch.atomicPrice),
    teamPriceAtomic: c.env.TEAM_PRICE_USDC_ATOMIC || '49000000',
    minConfirmations: Number(c.env.MIN_CONFIRMATIONS || '2'),
    supportEmail: 'apexhive.hq@proton.me',
    batchName: batch.name,
    soldIndieCount: soldCount,
    slotsRemainingInBatch: batch.threshold === Infinity ? null : Math.max(0, batch.threshold - soldCount)
  });
});

app.get('/api/config', async (c) => {
  const soldCountRaw = await c.env.LICENSES_KV.get('stats:sold_indie');
  const soldCount = soldCountRaw ? Number(soldCountRaw) : 0;
  const batch = getActiveBatch(soldCount);
  const slotsLeft = batch.threshold === Infinity ? null : Math.max(0, batch.threshold - soldCount);

  return c.json({
    brand: c.env.BRAND_NAME,
    product: c.env.PRODUCT_ID,
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress: c.env.PAY_TO_EVM_ADDRESS,
    publicKeySpkiB64: c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? null,
    tiers: {
      indie: {
        label: `Pro Indie — ${batch.name}`,
        usdc: String(Number(batch.atomicPrice) / 1_000_000),
        regularUsdc: '19',
        atomic: String(batch.atomicPrice),
        batchName: batch.name,
        slotsRemainingInBatch: slotsLeft
      },
      team: {
        label: 'Pro Team (5 Seats, Lifetime)',
        usdc: '49',
        atomic: c.env.TEAM_PRICE_USDC_ATOMIC || '49000000'
      }
    },
    supportEmail: 'apexhive.hq@proton.me',
    optionalRails: {
      solanaUsdc: c.env.SOLANA_RECEIVE_ADDRESS,
      bitcoin: c.env.BTC_RECEIVE_ADDRESS,
      tronTrxUsdt: c.env.TRON_RECEIVE_ADDRESS
    },
    selfCustodyWarning:
      'IMPORTANT: Send Base USDC ONLY from a self-custody wallet (MetaMask, Rabby, Coinbase Wallet). NEVER send directly from a centralized exchange (CEX) withdrawal, because you must sign an EIP-191 ownership message with the exact sending wallet. Sent from a CEX or paying via Solana/BTC/TRON? Contact apexhive.hq@proton.me with your txHash.'
  });
});

app.post('/api/challenge', async (c) => {
  let body: { txHash?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const tier = (body.tier ?? 'indie').trim() as Tier;

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (tier !== 'indie' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be indie or team.' }, 400);
  }

  let lockedAtomic: bigint;
  if (tier === 'team') {
    lockedAtomic = BigInt(c.env.TEAM_PRICE_USDC_ATOMIC || '49000000');
  } else {
    const soldCountRaw = await c.env.LICENSES_KV.get('stats:sold_indie');
    const soldCount = soldCountRaw ? Number(soldCountRaw) : 0;
    lockedAtomic = getActiveBatch(soldCount).atomicPrice;
  }

  const nonce = randomHex(16);
  const ts = Math.floor(Date.now() / 1000);
  const message = buildChallengeMessage({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'slimmcp-proxy',
    tier,
    txHash,
    nonce,
    ts
  });

  const record: ChallengeRecord = {
    nonce,
    txHash: txHash.toLowerCase(),
    tier,
    ts,
    message,
    lockedAtomic: String(lockedAtomic)
  };

  await c.env.LICENSES_KV.put(`challenge:${nonce}`, JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS
  });

  return c.json({
    nonce,
    ts,
    expiresInSeconds: CHALLENGE_TTL_SECONDS,
    message
  });
});

app.post('/api/verify', async (c) => {
  // Check server secrets & shared KV binding BEFORE reading/deleting any KV nonces
  if (!c.env.LICENSE_SIGNING_PRIVATE_JWK || !c.env.GLOBAL_CLAIMED_TX_KV) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing signing secret or GLOBAL_CLAIMED_TX_KV.' },
      500
    );
  }

  let body: { txHash?: string; nonce?: string; signature?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const nonce = (body.nonce ?? '').trim();
  const signature = (body.signature ?? '').trim();
  const tier = (body.tier ?? 'indie').trim() as Tier;

  if (!TX_HASH_RE.test(txHash) || !nonce || !SIG_RE.test(signature)) {
    return c.json(
      { error: 'INVALID_REQUEST', message: 'Provide valid txHash, nonce, and EIP-191 signature.' },
      400
    );
  }
  if (tier !== 'indie' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be indie or team.' }, 400);
  }

  const txLower = txHash.toLowerCase();
  const challengeKey = `challenge:${nonce}`;
  const challengeRaw = await c.env.LICENSES_KV.get(challengeKey);
  if (!challengeRaw) {
    return c.json(
      { error: 'CHALLENGE_EXPIRED_OR_MISSING', message: 'Challenge expired (>300s) or unknown.' },
      403
    );
  }

  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  const nowSec = Math.floor(Date.now() / 1000);
  if (
    challenge.txHash !== txLower ||
    challenge.tier !== tier ||
    nowSec - challenge.ts > CHALLENGE_TTL_SECONDS
  ) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json(
      { error: 'CHALLENGE_MISMATCH_OR_EXPIRED', message: 'Challenge mismatch or expired.' },
      403
    );
  }

  const rpcUrls = getBaseRpcUrls(c.env);
  let receipt: RpcReceipt | null;
  let latestBlockHex: string;
  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCallWithFailover<RpcReceipt | null>(rpcUrls, 'eth_getTransactionReceipt', [txLower]),
      rpcCallWithFailover<string>(rpcUrls, 'eth_blockNumber', [])
    ]);
  } catch (err) {
    return c.json(
      {
        error: 'RPC_UNAVAILABLE',
        message: err instanceof Error ? err.message : 'Base RPC error'
      },
      502
    );
  }

  if (!receipt || receipt.status !== '0x1') {
    return c.json(
      { error: 'TX_NOT_CONFIRMED', message: 'Transaction receipt missing or reverted.' },
      403
    );
  }

  const txBlock = parseStrictHexBigInt(receipt.blockNumber);
  const headBlock = parseStrictHexBigInt(latestBlockHex);
  if (txBlock === null || headBlock === null) {
    return c.json(
      { error: 'TX_NOT_CONFIRMED', message: 'Malformed or non-hex blockNumber from RPC.' },
      403
    );
  }

  const minConf = Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2'));
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
  if (confirmations < minConf) {
    return c.json(
      {
        error: 'INSUFFICIENT_CONFIRMATIONS',
        message: `Need >= ${minConf} confirmations (got ${confirmations}). Retry shortly with the same challenge.`
      },
      403
    );
  }

  const lockedAtomic = BigInt(challenge.lockedAtomic || (tier === 'team' ? '49000000' : '5000000'));
  const acceptedAtomics = new Set<bigint>([lockedAtomic]);
  if (tier === 'indie') {
    const graceRaw = await c.env.LICENSES_KV.get('batch_grace:indie');
    if (graceRaw) {
      const grace = JSON.parse(graceRaw) as BatchGrace;
      if (Date.now() < grace.graceUntilMs) {
        acceptedAtomics.add(BigInt(grace.prevAtomic));
      }
    }
  }

  const payerTotals = sumBaseUsdcTransfers(
    receipt.logs,
    c.env.BASE_USDC_CONTRACT,
    c.env.PAY_TO_EVM_ADDRESS
  );

  let matchedPayer: string | null = null;
  let paidAtomic = 0n;
  for (const [fromAddr, totalPaid] of payerTotals.entries()) {
    const meetsPrice = [...acceptedAtomics].some((p) => totalPaid >= p);
    if (!meetsPrice) continue;

    const sigOk = await verifyMessage({
      address: fromAddr as `0x${string}`,
      message: challenge.message,
      signature: signature as `0x${string}`
    }).catch(() => false);
    if (sigOk) {
      matchedPayer = fromAddr;
      paidAtomic = totalPaid;
      break;
    }
  }

  if (!matchedPayer) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json(
      {
        error: 'PAYMENT_OR_SIGNATURE_INVALID',
        message:
          'No Base USDC Transfer to the ApexHive Labs receive address met the tier price with a matching EIP-191 payer signature.'
      },
      403
    );
  }

  // Check cross-product & cross-endpoint shared anti-replay BEFORE issuing license
  const globalKey = `global_tx:${txLower}`;
  const globalRaw = await c.env.GLOBAL_CLAIMED_TX_KV.get(globalKey);
  if (globalRaw) {
    const globalRec = JSON.parse(globalRaw) as GlobalClaimRecord;
    if (globalRec.scope !== SCOPE_STOREFRONT) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json(
        {
          error: 'TX_ALREADY_CLAIMED_ELSEWHERE',
          message: `This transaction hash has already been claimed on ${globalRec.scope}.`
        },
        403
      );
    }
    if (
      globalRec.payer?.toLowerCase() !== matchedPayer.toLowerCase() ||
      globalRec.tier !== tier
    ) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json(
        { error: 'TX_ALREADY_CLAIMED', message: 'This transaction hash has already claimed a license.' },
        403
      );
    }
  }

  // Consume single-use challenge after payment, signature, and global scope checks pass
  await c.env.LICENSES_KV.delete(challengeKey);

  const claimedKey = `claimed_tx:${txLower}`;
  const existingClaimRaw = await c.env.LICENSES_KV.get(claimedKey);

  let reclaimed = false;
  if (existingClaimRaw) {
    const existing = JSON.parse(existingClaimRaw) as { payer?: string; tier?: Tier };
    if (
      existing.payer?.toLowerCase() === matchedPayer.toLowerCase() &&
      existing.tier === tier
    ) {
      reclaimed = true;
    } else {
      return c.json(
        { error: 'TX_ALREADY_CLAIMED', message: 'This transaction hash has already claimed a license.' },
        403
      );
    }
  }

  const issuedAt = Date.now();
  const licenseToken = await signLicenseToken(c.env, {
    v: 1,
    product: 'slimmcp-proxy',
    tier,
    payer: matchedPayer,
    txHash: txLower,
    issuedAt,
    expiresAt: null
  });

  if (!reclaimed) {
    const globalRecord: GlobalClaimRecord = {
      scope: SCOPE_STOREFRONT,
      payer: matchedPayer,
      tier,
      txHash: txLower,
      claimedAt: issuedAt
    };
    await Promise.all([
      c.env.LICENSES_KV.put(
        claimedKey,
        JSON.stringify({ txHash: txLower, payer: matchedPayer, tier, issuedAt })
      ),
      c.env.GLOBAL_CLAIMED_TX_KV.put(globalKey, JSON.stringify(globalRecord))
    ]);

    if (tier === 'indie') {
      const prevSoldRaw = await c.env.LICENSES_KV.get('stats:sold_indie');
      const prevSold = prevSoldRaw ? Number(prevSoldRaw) : 0;
      const newSold = prevSold + 1;
      await c.env.LICENSES_KV.put('stats:sold_indie', String(newSold));

      const prevBatch = getActiveBatch(prevSold);
      const newBatch = getActiveBatch(newSold);
      if (prevBatch.atomicPrice !== newBatch.atomicPrice) {
        const grace: BatchGrace = {
          prevAtomic: String(prevBatch.atomicPrice),
          graceUntilMs: Date.now() + GRACE_MS
        };
        await c.env.LICENSES_KV.put('batch_grace:indie', JSON.stringify(grace), {
          expirationTtl: Math.ceil(GRACE_MS / 1000) + 10
        });
      }
    }
  }

  return c.json({
    ok: true,
    reclaimed,
    tier,
    payer: matchedPayer,
    txHash: txLower,
    paidAtomic: String(paidAtomic),
    licenseToken,
    activationCommand: `node dist/src/cli.js activate --token "${licenseToken}"`
  });
});

// ─── Free Zero-Install Browser Playground ────────────────────────────────────

app.post('/api/playground/compress', async (c) => {
  const rawText = await c.req.text();
  const result = compressMcpToolsPayload(rawText);
  if (!result.ok) {
    return c.json({ error: result.error, message: result.message }, result.status);
  }
  return c.json(result, 200);
});

// ─── Agent x402 Micro-Pay API ($0.005 USDC / 5000 atomic on Base + EIP-191) ─

app.post('/api/x402/compress', async (c) => {
  if (!c.env.GLOBAL_CLAIMED_TX_KV) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing GLOBAL_CLAIMED_TX_KV binding.' },
      500
    );
  }

  const rawText = await c.req.text();
  const rawBytes = new TextEncoder().encode(rawText).length;
  if (rawBytes > MAX_PLAYGROUND_BYTES) {
    return c.json(
      { error: 'PAYLOAD_TOO_LARGE', message: `Payload exceeds ${MAX_PLAYGROUND_BYTES} bytes limit.` },
      413
    );
  }

  let bodyPayment: {
    txHash?: string;
    signature?: string;
    address?: string;
  } = {};
  if (rawText.trim()) {
    try {
      const parsed = JSON.parse(rawText) as {
        paymentTxHash?: unknown;
        paymentSignature?: unknown;
        paymentAddress?: unknown;
        payment?: { txHash?: unknown; signature?: unknown; address?: unknown };
      };
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const tx = parsed.paymentTxHash ?? parsed.payment?.txHash;
        const sig = parsed.paymentSignature ?? parsed.payment?.signature;
        const addr = parsed.paymentAddress ?? parsed.payment?.address;
        if (typeof tx === 'string') bodyPayment.txHash = tx;
        if (typeof sig === 'string') bodyPayment.signature = sig;
        if (typeof addr === 'string') bodyPayment.address = addr;
      }
    } catch {
      // Malformed JSON handled below once payment gate clears
    }
  }

  const xPaymentRaw = (
    c.req.header('X-Payment') ??
    c.req.header('x-payment') ??
    bodyPayment.txHash ??
    ''
  ).trim();
  const xSigRaw = (
    c.req.header('X-Payment-Signature') ??
    c.req.header('x-payment-signature') ??
    bodyPayment.signature ??
    ''
  ).trim();
  const xAddrRaw = (
    c.req.header('X-Payment-Address') ??
    c.req.header('x-payment-address') ??
    bodyPayment.address ??
    ''
  ).trim();

  if (!xPaymentRaw) {
    const origin = new URL(c.req.url).origin;
    return c.json(
      buildX402PaymentRequiredV2(c.env, origin),
      402,
      { 'X-Payment-Required': 'true' }
    );
  }

  if (!TX_HASH_RE.test(xPaymentRaw)) {
    return c.json(
      { error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash in X-Payment.' },
      400
    );
  }

  if (!xSigRaw || !xAddrRaw) {
    return c.json(
      {
        error: 'SIGNATURE_REQUIRED',
        message:
          'Provide X-Payment-Signature and X-Payment-Address signing "ApexHive x402 slimmcp-compress\\ntxHash:<txHash_lowercase>".'
      },
      401
    );
  }

  if (!SIG_RE.test(xSigRaw) || !EVM_ADDR_RE.test(xAddrRaw)) {
    return c.json(
      { error: 'INVALID_PAYMENT_SIGNATURE', message: 'Malformed X-Payment-Signature or X-Payment-Address.' },
      403
    );
  }

  const txLower = xPaymentRaw.toLowerCase();
  const payerLower = xAddrRaw.toLowerCase();
  const expectedSignedMsg = `ApexHive x402 slimmcp-compress\ntxHash:${txLower}`;
  const sigOk = await verifyMessage({
    address: payerLower as `0x${string}`,
    message: expectedSignedMsg,
    signature: xSigRaw as `0x${string}`
  }).catch(() => false);

  if (!sigOk) {
    return c.json(
      {
        error: 'INVALID_PAYMENT_SIGNATURE',
        message: 'EIP-191 signature does not match X-Payment-Address and txHash.'
      },
      403
    );
  }

  const compressed = compressMcpToolsPayload(rawText);
  if (!compressed.ok) {
    return c.json({ error: compressed.error, message: compressed.message }, compressed.status);
  }

  const globalKey = `global_tx:${txLower}`;
  const existingGlobalRaw = await c.env.GLOBAL_CLAIMED_TX_KV.get(globalKey);
  if (existingGlobalRaw) {
    const existingGlobal = JSON.parse(existingGlobalRaw) as GlobalClaimRecord;
    if (existingGlobal.scope !== SCOPE_X402) {
      return c.json(
        {
          error: 'TX_ALREADY_CLAIMED_ELSEWHERE',
          message: `This transaction hash has already been claimed on ${existingGlobal.scope}.`
        },
        403
      );
    }
    return c.json(
      { error: 'TX_ALREADY_CLAIMED', message: 'This x402 transaction hash has already been redeemed.' },
      403
    );
  }

  const x402Key = `x402_claimed:${txLower}`;
  const alreadyClaimed = await c.env.LICENSES_KV.get(x402Key);
  if (alreadyClaimed) {
    return c.json(
      { error: 'TX_ALREADY_CLAIMED', message: 'This x402 transaction hash has already been redeemed.' },
      403
    );
  }

  const rpcUrls = getBaseRpcUrls(c.env);
  let receipt: RpcReceipt | null;
  let latestBlockHex: string;
  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCallWithFailover<RpcReceipt | null>(rpcUrls, 'eth_getTransactionReceipt', [txLower]),
      rpcCallWithFailover<string>(rpcUrls, 'eth_blockNumber', [])
    ]);
  } catch (err) {
    return c.json(
      { error: 'RPC_UNAVAILABLE', message: err instanceof Error ? err.message : 'Base RPC error' },
      502
    );
  }

  if (!receipt || receipt.status !== '0x1') {
    return c.json(
      { error: 'TX_NOT_CONFIRMED', message: 'Transaction receipt missing or reverted.' },
      403
    );
  }

  const txBlock = parseStrictHexBigInt(receipt.blockNumber);
  const headBlock = parseStrictHexBigInt(latestBlockHex);
  if (txBlock === null || headBlock === null) {
    return c.json(
      { error: 'TX_NOT_CONFIRMED', message: 'Malformed or non-hex blockNumber from RPC.' },
      403
    );
  }

  const minConf = Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2'));
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
  if (confirmations < minConf) {
    return c.json(
      {
        error: 'INSUFFICIENT_CONFIRMATIONS',
        message: `Need >= ${minConf} confirmations (got ${confirmations}).`
      },
      403
    );
  }

  const payerTotals = sumBaseUsdcTransfers(
    receipt.logs,
    c.env.BASE_USDC_CONTRACT,
    c.env.PAY_TO_EVM_ADDRESS
  );
  const senderPaid = payerTotals.get(payerLower) ?? 0n;
  if (senderPaid < X402_PRICE_ATOMIC) {
    return c.json(
      {
        error: 'PAYMENT_INSUFFICIENT',
        message: `Expected >= ${X402_PRICE_ATOMIC.toString()} atomic Base USDC transfer from ${payerLower} to ${c.env.PAY_TO_EVM_ADDRESS}.`
      },
      403
    );
  }

  const verifiedAt = Date.now();
  const globalRecord: GlobalClaimRecord = {
    scope: SCOPE_X402,
    payer: payerLower,
    tier: 'x402',
    txHash: txLower,
    claimedAt: verifiedAt
  };
  await Promise.all([
    c.env.LICENSES_KV.put(
      x402Key,
      JSON.stringify({ txHash: txLower, payer: payerLower, paidAtomic: senderPaid.toString(), verifiedAt })
    ),
    c.env.GLOBAL_CLAIMED_TX_KV.put(globalKey, JSON.stringify(globalRecord))
  ]);

  return c.json({
    ...compressed,
    payment: {
      settled: true,
      txHash: txLower,
      payer: payerLower,
      paidAtomic: senderPaid.toString(),
      confirmations,
      network: 'base',
      chainId: Number(c.env.BASE_CHAIN_ID || '8453')
    }
  });
});

app.all('*', async (c) => {
  if (c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw);
  }
  return c.text('Not Found', 404);
});

export default app;
