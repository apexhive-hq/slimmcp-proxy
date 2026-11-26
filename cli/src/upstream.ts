import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { FetchLike, Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { RawMcpTool, UpstreamServerConfig } from './types.js';
import { SLIMMCP_VERSION } from './version.js';

export const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

export const DEFAULT_ENV_ALLOWLIST = [
  'PATH',
  'HOME',
  'USERPROFILE',
  'SYSTEMROOT',
  'COMSPEC',
  'TMP',
  'TEMP',
  'LANG',
  'NODE_ENV'
] as const;

export interface UpstreamManagerOptions {
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
}

interface ConnectedUpstream {
  config: UpstreamServerConfig;
  client: Client;
  transport: Transport;
  tools: RawMcpTool[];
  requestTimeoutMs: number;
}

/**
 * Builds an isolated child environment using only a minimal safe allowlist,
 * optional per-server allowlisted keys, and explicit `spec.env` overrides.
 */
export function buildIsolatedChildEnv(
  explicitEnv?: Record<string, string>,
  envAllowlist?: string[],
  sourceEnv: NodeJS.ProcessEnv = process.env
): Record<string, string> {
  const out: Record<string, string> = {};
  const allowedKeys = new Set<string>(DEFAULT_ENV_ALLOWLIST);

  if (envAllowlist) {
    for (const key of envAllowlist) {
      const trimmed = key.trim();
      if (trimmed) allowedKeys.add(trimmed);
    }
  }

  for (const key of allowedKeys) {
    const val = sourceEnv[key];
    if (typeof val === 'string' && !val.startsWith('()')) {
      out[key] = val;
    }
  }

  if (explicitEnv) {
    for (const [k, v] of Object.entries(explicitEnv)) {
      if (typeof v === 'string') {
        out[k] = v;
      }
    }
  }

  return out;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${label} timed out after ${timeoutMs}ms.`));
        }, timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

const BLOCKED_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  '100.100.100.200',
  'fd00:ec2::254'
]);

function parseIpv6Groups(host: string): number[] | null {
  if (!host.includes(':')) return null;
  const zoneIdx = host.indexOf('%');
  const clean = zoneIdx === -1 ? host : host.slice(0, zoneIdx);

  const doubleColonParts = clean.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSegmentList = (seg: string): number[] | null => {
    if (!seg) return [];
    const parts = seg.split(':');
    const out: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part.includes('.')) {
        if (i !== parts.length - 1) return null;
        const octets = part.split('.');
        if (octets.length !== 4) return null;
        const nums = octets.map((o) => (/^\d+$/.test(o) ? Number(o) : -1));
        if (nums.some((n) => n < 0 || n > 255)) return null;
        out.push((nums[0] << 8) | nums[1], (nums[2] << 8) | nums[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
        out.push(Number.parseInt(part, 16));
      }
    }
    return out;
  };

  const left = parseSegmentList(doubleColonParts[0]);
  if (!left) return null;

  if (doubleColonParts.length === 1) {
    return left.length === 8 ? left : null;
  }

  const right = parseSegmentList(doubleColonParts[1]);
  if (!right) return null;

  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;

  return [...left, ...Array<number>(missing).fill(0), ...right];
}

function isBlockedIpv4(ip: string): boolean {
  return BLOCKED_METADATA_HOSTS.has(ip) || ip.startsWith('169.254.');
}

/**
 * Validates that an upstream remote URL uses http:/https: and does not target
 * cloud instance metadata or link-local metadata endpoints (including IPv4-mapped IPv6).
 */
export function validateUpstreamUrl(urlStr: string): URL {
  const parsed = new URL(urlStr);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported upstream URL scheme "${parsed.protocol}"; only http: and https: are allowed.`);
  }
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, '').replace(/^\[|\]$/g, '');
  if (BLOCKED_METADATA_HOSTS.has(host) || isBlockedIpv4(host)) {
    throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
  }

  const ipv6 = parseIpv6Groups(host);
  if (ipv6) {
    // ::/128 unspecified IPv6 address
    if (ipv6.every((g) => g === 0)) {
      throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
    }
    // 64:ff9b::/96 NAT64 well-known prefix
    if (
      ipv6[0] === 0x0064 &&
      ipv6[1] === 0xff9b &&
      ipv6[2] === 0 &&
      ipv6[3] === 0 &&
      ipv6[4] === 0 &&
      ipv6[5] === 0
    ) {
      throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
    }
    // fe80::/10 link-local
    if ((ipv6[0] & 0xffc0) === 0xfe80) {
      throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
    }
    // fd00:ec2::254 (AWS IPv6 IMDS)
    if (
      ipv6[0] === 0xfd00 &&
      ipv6[1] === 0x0ec2 &&
      ipv6[2] === 0 &&
      ipv6[3] === 0 &&
      ipv6[4] === 0 &&
      ipv6[5] === 0 &&
      ipv6[6] === 0 &&
      ipv6[7] === 0x0254
    ) {
      throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
    }
    // IPv4-mapped IPv6 (::ffff:a.b.c.d / ::ffff:xxxx:yyyy) or IPv4-compatible (::a.b.c.d)
    const isIpv4Mapped =
      ipv6[0] === 0 &&
      ipv6[1] === 0 &&
      ipv6[2] === 0 &&
      ipv6[3] === 0 &&
      ipv6[4] === 0 &&
      ipv6[5] === 0xffff;
    const isIpv4Compat =
      ipv6[0] === 0 &&
      ipv6[1] === 0 &&
      ipv6[2] === 0 &&
      ipv6[3] === 0 &&
      ipv6[4] === 0 &&
      ipv6[5] === 0 &&
      (ipv6[6] !== 0 || ipv6[7] > 1);
    if (isIpv4Mapped || isIpv4Compat) {
      const mappedIpv4 = [
        (ipv6[6] >> 8) & 0xff,
        ipv6[6] & 0xff,
        (ipv6[7] >> 8) & 0xff,
        ipv6[7] & 0xff
      ].join('.');
      if (isBlockedIpv4(mappedIpv4)) {
        throw new Error(`Blocked cloud metadata / link-local upstream host "${parsed.hostname}".`);
      }
    }
  }

  return parsed;
}

const safeUpstreamFetch: FetchLike = (url, init) => {
  validateUpstreamUrl(typeof url === 'string' ? url : url.toString());
  return fetch(url, { ...init, redirect: 'error' });
};

function buildRemoteTransport(
  urlStr: string,
  kind: 'streamable-http' | 'sse',
  headers?: Record<string, string>
): Transport {
  const endpoint = validateUpstreamUrl(urlStr);
  const requestInit: RequestInit = {
    ...(headers ? { headers } : {}),
    redirect: 'error'
  };
  if (kind === 'sse') {
    return new SSEClientTransport(endpoint, { requestInit, fetch: safeUpstreamFetch });
  }
  return new StreamableHTTPClientTransport(endpoint, { requestInit, fetch: safeUpstreamFetch });
}

async function connectWithTransport(
  transport: Transport,
  connectTimeoutMs: number
): Promise<{ client: Client; tools: RawMcpTool[] }> {
  const client = new Client(
    { name: 'slimmcp-proxy-client', version: SLIMMCP_VERSION },
    { capabilities: {} }
  );

  try {
    await withTimeout(
      client.connect(transport, { timeout: connectTimeoutMs }),
      connectTimeoutMs,
      'Upstream connect'
    );
    const listResult = await withTimeout(
      client.listTools(undefined, { timeout: connectTimeoutMs }),
      connectTimeoutMs,
      'Upstream listTools'
    );
    const tools: RawMcpTool[] = (listResult.tools ?? []).map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: (t.inputSchema as Record<string, unknown>) ?? {
        type: 'object',
        properties: {}
      }
    }));
    return { client, tools };
  } catch (err) {
    await client.close().catch(() => {});
    await transport.close().catch(() => {});
    throw err;
  }
}

export class UpstreamManager {
  private connections = new Map<string, ConnectedUpstream>();
  private defaultConnectTimeoutMs: number;
  private defaultRequestTimeoutMs: number;

  constructor(options?: UpstreamManagerOptions) {
    this.defaultConnectTimeoutMs = options?.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.defaultRequestTimeoutMs = options?.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  async connectAll(configs: UpstreamServerConfig[]): Promise<
    Array<{ serverId: string; tools: RawMcpTool[] }>
  > {
    const results: Array<{ serverId: string; tools: RawMcpTool[] }> = [];

    for (const cfg of configs) {
      const connectTimeoutMs = cfg.connectTimeoutMs ?? this.defaultConnectTimeoutMs;
      const requestTimeoutMs = cfg.requestTimeoutMs ?? this.defaultRequestTimeoutMs;
      let transport: Transport;
      let connected: { client: Client; tools: RawMcpTool[] };

      if (cfg.url) {
        const preferred = cfg.transport === 'sse' ? 'sse' : 'streamable-http';
        transport = buildRemoteTransport(cfg.url, preferred, cfg.headers);
        try {
          connected = await connectWithTransport(transport, connectTimeoutMs);
        } catch (err) {
          // If transport wasn't pinned to 'streamable-http', retry once with legacy SSE transport
          if (cfg.transport === undefined) {
            await transport.close().catch(() => {});
            transport = buildRemoteTransport(cfg.url, 'sse', cfg.headers);
            connected = await connectWithTransport(transport, connectTimeoutMs);
          } else {
            throw err;
          }
        }
      } else {
        if (!cfg.command) {
          throw new Error(`Upstream "${cfg.id}" requires either "command" or "url".`);
        }
        const isolatedEnv = buildIsolatedChildEnv(cfg.env, cfg.envAllowlist);

        const stdioTransport = new StdioClientTransport({
          command: cfg.command,
          args: cfg.args ?? [],
          env: isolatedEnv,
          cwd: cfg.cwd,
          stderr: 'pipe'
        });
        // Drain piped stderr so noisy upstreams never deadlock on full pipe buffers
        stdioTransport.stderr?.on('data', () => {});
        transport = stdioTransport;
        connected = await connectWithTransport(transport, connectTimeoutMs);
      }

      this.connections.set(cfg.id, {
        config: cfg,
        client: connected.client,
        transport,
        tools: connected.tools,
        requestTimeoutMs
      });
      results.push({ serverId: cfg.id, tools: connected.tools });
    }

    return results;
  }

  async callTool(
    serverId: string,
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean }> {
    const conn = this.connections.get(serverId);
    if (!conn) {
      throw new Error(`Unknown upstream server "${serverId}".`);
    }
    const result = await withTimeout(
      conn.client.callTool(
        {
          name: toolName,
          arguments: args
        },
        undefined,
        { timeout: conn.requestTimeoutMs }
      ),
      conn.requestTimeoutMs,
      `Upstream callTool "${serverId}:${toolName}"`
    );
    return result as {
      content: Array<{ type: string; text?: string; [k: string]: unknown }>;
      isError?: boolean;
    };
  }

  async closeAll(): Promise<void> {
    for (const conn of this.connections.values()) {
      try {
        await conn.client.close();
      } catch {
        // Ignore teardown errors during shutdown
      }
    }
    this.connections.clear();
  }
}
