import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { RawMcpTool, UpstreamServerConfig } from './types.js';

interface ConnectedUpstream {
  config: UpstreamServerConfig;
  client: Client;
  transport: Transport;
  tools: RawMcpTool[];
}

function buildRemoteTransport(
  urlStr: string,
  kind: 'streamable-http' | 'sse',
  headers?: Record<string, string>
): Transport {
  const endpoint = new URL(urlStr);
  const requestInit = headers ? { headers } : undefined;
  if (kind === 'sse') {
    return new SSEClientTransport(endpoint, { requestInit });
  }
  return new StreamableHTTPClientTransport(endpoint, { requestInit });
}

async function connectWithTransport(transport: Transport): Promise<{ client: Client; tools: RawMcpTool[] }> {
  const client = new Client(
    { name: 'slimmcp-proxy-client', version: '1.0.2' },
    { capabilities: {} }
  );
  await client.connect(transport);
  const listResult = await client.listTools();
  const tools: RawMcpTool[] = (listResult.tools ?? []).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: (t.inputSchema as Record<string, unknown>) ?? {
      type: 'object',
      properties: {}
    }
  }));
  return { client, tools };
}

export class UpstreamManager {
  private connections = new Map<string, ConnectedUpstream>();

  async connectAll(configs: UpstreamServerConfig[]): Promise<
    Array<{ serverId: string; tools: RawMcpTool[] }>
  > {
    const results: Array<{ serverId: string; tools: RawMcpTool[] }> = [];

    for (const cfg of configs) {
      let transport: Transport;
      let connected: { client: Client; tools: RawMcpTool[] };

      if (cfg.url) {
        const preferred = cfg.transport === 'sse' ? 'sse' : 'streamable-http';
        transport = buildRemoteTransport(cfg.url, preferred, cfg.headers);
        try {
          connected = await connectWithTransport(transport);
        } catch (err) {
          // If transport wasn't pinned to 'streamable-http', retry once with legacy SSE transport
          if (cfg.transport === undefined) {
            await transport.close().catch(() => {});
            transport = buildRemoteTransport(cfg.url, 'sse', cfg.headers);
            connected = await connectWithTransport(transport);
          } else {
            throw err;
          }
        }
      } else {
        if (!cfg.command) {
          throw new Error(`Upstream "${cfg.id}" requires either "command" or "url".`);
        }
        const mergedEnv = cfg.env
          ? Object.fromEntries(
              Object.entries({ ...process.env, ...cfg.env }).filter(
                (pair): pair is [string, string] => typeof pair[1] === 'string'
              )
            )
          : undefined;

        transport = new StdioClientTransport({
          command: cfg.command,
          args: cfg.args ?? [],
          env: mergedEnv,
          cwd: cfg.cwd,
          stderr: 'pipe'
        });
        connected = await connectWithTransport(transport);
      }

      this.connections.set(cfg.id, {
        config: cfg,
        client: connected.client,
        transport,
        tools: connected.tools
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
    const result = await conn.client.callTool({
      name: toolName,
      arguments: args
    });
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
