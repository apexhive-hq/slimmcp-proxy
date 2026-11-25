import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { RawMcpTool, UpstreamServerConfig } from './types.js';

interface ConnectedUpstream {
  config: UpstreamServerConfig;
  client: Client;
  transport: StdioClientTransport;
  tools: RawMcpTool[];
}

export class UpstreamManager {
  private connections = new Map<string, ConnectedUpstream>();

  async connectAll(configs: UpstreamServerConfig[]): Promise<
    Array<{ serverId: string; tools: RawMcpTool[] }>
  > {
    const results: Array<{ serverId: string; tools: RawMcpTool[] }> = [];

    for (const cfg of configs) {
      const mergedEnv = cfg.env
        ? Object.fromEntries(
            Object.entries({ ...process.env, ...cfg.env }).filter(
              (pair): pair is [string, string] => typeof pair[1] === 'string'
            )
          )
        : undefined;

      const transport = new StdioClientTransport({
        command: cfg.command,
        args: cfg.args ?? [],
        env: mergedEnv,
        cwd: cfg.cwd,
        stderr: 'pipe'
      });

      const client = new Client(
        { name: 'slimmcp-proxy-client', version: '1.0.0' },
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

      this.connections.set(cfg.id, {
        config: cfg,
        client,
        transport,
        tools
      });
      results.push({ serverId: cfg.id, tools });
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
