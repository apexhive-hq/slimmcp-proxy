import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { ToolIndexer } from './indexer.js';
import { MetricsLedger } from './ledger.js';
import { PolicyGuard } from './policy.js';
import { redactSecrets } from './redactor.js';
import { countUtf8Bytes, estimateTokens } from './tokenizer.js';
import type { RawMcpTool, SlimMcpConfig } from './types.js';
import { UpstreamManager } from './upstream.js';

export const META_TOOLS: RawMcpTool[] = [
  {
    name: 'discover_tools',
    description:
      'Search connected MCP tools by keyword or intent. Returns compact tool names, 1-line summaries, and required argument names without loading full JSON schemas.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search keywords or "*" to list tools.'
        },
        server: {
          type: 'string',
          description: 'Optional upstream server ID filter.'
        },
        limit: {
          type: 'number',
          description: 'Max results to return (1-25, default 8).'
        }
      },
      required: ['query']
    }
  },
  {
    name: 'inspect_tool_schema',
    description:
      'Fetch the exact JSON inputSchema for a single discovered MCP tool before invoking it.',
    inputSchema: {
      type: 'object',
      properties: {
        server: { type: 'string', description: 'Upstream server ID.' },
        tool: { type: 'string', description: 'Exact tool name.' }
      },
      required: ['server', 'tool']
    }
  },
  {
    name: 'invoke_tool',
    description:
      'Execute a specific upstream MCP tool with secret redaction and local RBAC policy/spend-cap enforcement.',
    inputSchema: {
      type: 'object',
      properties: {
        server: { type: 'string', description: 'Upstream server ID.' },
        tool: { type: 'string', description: 'Exact tool name.' },
        arguments: {
          type: 'object',
          description: 'Arguments object matching inspect_tool_schema.'
        }
      },
      required: ['server', 'tool']
    }
  }
];

const DiscoverInputSchema = z.object({
  query: z.string().default('*'),
  server: z.string().optional(),
  limit: z.number().int().min(1).max(25).optional()
});

const InspectInputSchema = z.object({
  server: z.string().min(1),
  tool: z.string().min(1)
});

const InvokeInputSchema = z.object({
  server: z.string().min(1),
  tool: z.string().min(1),
  arguments: z.record(z.unknown()).optional()
});

export interface SlimProxyRuntimeOptions {
  config: SlimMcpConfig;
  upstream: UpstreamManager;
  indexer: ToolIndexer;
  policyGuard: PolicyGuard;
  ledger: MetricsLedger;
  sessionId: number;
}

export class SlimProxyCore {
  private opts: SlimProxyRuntimeOptions;

  constructor(opts: SlimProxyRuntimeOptions) {
    this.opts = opts;
  }

  async handleListTools() {
    return { tools: META_TOOLS };
  }

  async handleCallTool(name: string, rawArgs: unknown) {
    const start = performance.now();
    const { config, upstream, indexer, policyGuard, ledger, sessionId } = this.opts;

    if (name === 'discover_tools') {
      const parsed = DiscoverInputSchema.safeParse(rawArgs ?? {});
      if (!parsed.success) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Invalid discover_tools args: ${parsed.error.message}` }]
        };
      }
      const matches = indexer.search(parsed.data.query, {
        server: parsed.data.server,
        limit: parsed.data.limit
      });
      const elapsed = performance.now() - start;
      ledger.recordEvent({
        sessionId,
        kind: 'discover_tools',
        tokensSaved: 0,
        status: 'allowed',
        latencyMs: elapsed
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ matches, totalIndexedTools: indexer.getAllTools().length })
          }
        ]
      };
    }

    if (name === 'inspect_tool_schema') {
      const parsed = InspectInputSchema.safeParse(rawArgs ?? {});
      if (!parsed.success) {
        return {
          isError: true,
          content: [
            { type: 'text', text: `Invalid inspect_tool_schema args: ${parsed.error.message}` }
          ]
        };
      }
      const tool = indexer.getTool(parsed.data.server, parsed.data.tool);
      const elapsed = performance.now() - start;
      if (!tool) {
        ledger.recordEvent({
          sessionId,
          kind: 'inspect_tool_schema',
          serverId: parsed.data.server,
          toolName: parsed.data.tool,
          status: 'error',
          latencyMs: elapsed
        });
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Tool "${parsed.data.server}:${parsed.data.tool}" not found. Call discover_tools first.`
            }
          ]
        };
      }

      ledger.recordEvent({
        sessionId,
        kind: 'inspect_tool_schema',
        serverId: tool.serverId,
        toolName: tool.name,
        status: 'allowed',
        latencyMs: elapsed
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              server: tool.serverId,
              tool: tool.name,
              description: tool.description,
              inputSchema: tool.inputSchema
            })
          }
        ]
      };
    }

    if (name === 'invoke_tool') {
      const parsed = InvokeInputSchema.safeParse(rawArgs ?? {});
      if (!parsed.success) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Invalid invoke_tool args: ${parsed.error.message}` }]
        };
      }

      const { server, tool } = parsed.data;
      const indexedTool = indexer.getTool(server, tool);
      if (!indexedTool) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Tool "${server}:${tool}" not found. Call discover_tools first.`
            }
          ]
        };
      }

      const decision = policyGuard.evaluate(server, tool);
      if (!decision.allowed) {
        const elapsed = performance.now() - start;
        const status =
          decision.code === 'DENIED_BY_POLICY'
            ? 'blocked_policy'
            : 'blocked_cap';
        ledger.recordEvent({
          sessionId,
          kind: 'invoke_tool',
          serverId: server,
          toolName: tool,
          status,
          latencyMs: elapsed
        });
        return {
          isError: true,
          content: [{ type: 'text', text: `[${decision.code}] ${decision.reason}` }]
        };
      }

      const redactionEnabled = config.redaction?.enabled ?? true;
      const redactInputs = redactionEnabled && (config.redaction?.redactInputs ?? true);
      const redactOutputs = redactionEnabled && (config.redaction?.redactOutputs ?? true);

      let callArgs = parsed.data.arguments ?? {};
      let redactionsCount = 0;
      if (redactInputs) {
        const res = redactSecrets(callArgs);
        callArgs = res.sanitized;
        redactionsCount += res.redactionCount;
      }

      try {
        let upstreamResult = await upstream.callTool(server, tool, callArgs);
        if (redactOutputs) {
          const outRes = redactSecrets(upstreamResult);
          upstreamResult = outRes.sanitized;
          redactionsCount += outRes.redactionCount;
        }
        const elapsed = performance.now() - start;
        ledger.recordEvent({
          sessionId,
          kind: 'invoke_tool',
          serverId: server,
          toolName: tool,
          status: 'allowed',
          latencyMs: elapsed,
          redactionsCount
        });
        return upstreamResult;
      } catch (err) {
        const elapsed = performance.now() - start;
        ledger.recordEvent({
          sessionId,
          kind: 'invoke_tool',
          serverId: server,
          toolName: tool,
          status: 'error',
          latencyMs: elapsed,
          redactionsCount
        });
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Upstream error calling ${server}:${tool}: ${
                err instanceof Error ? err.message : String(err)
              }`
            }
          ]
        };
      }
    }

    return {
      isError: true,
      content: [{ type: 'text', text: `Unknown meta-tool "${name}".` }]
    };
  }
}

export function computeSchemaSavings(
  serverTools: Array<{ serverId: string; tools: RawMcpTool[] }>
) {
  const allRawTools = serverTools.flatMap((s) => s.tools);
  const rawPayload = { tools: allRawTools };
  const slimPayload = { tools: META_TOOLS };

  const rawSchemaBytes = countUtf8Bytes(rawPayload);
  const rawSchemaTokens = estimateTokens(rawPayload);
  const slimExposedBytes = countUtf8Bytes(slimPayload);
  const slimExposedTokens = estimateTokens(slimPayload);

  const tokensSaved = Math.max(0, rawSchemaTokens - slimExposedTokens);
  const reductionPercent =
    rawSchemaTokens > 0
      ? Number(((tokensSaved / rawSchemaTokens) * 100).toFixed(2))
      : 0;

  return {
    rawToolsCount: allRawTools.length,
    rawSchemaBytes,
    rawSchemaTokens,
    slimToolsCount: META_TOOLS.length,
    slimExposedBytes,
    slimExposedTokens,
    tokensSaved,
    reductionPercent
  };
}

export async function startStdioProxyServer(
  core: SlimProxyCore,
  upstream: UpstreamManager,
  ledger: MetricsLedger
): Promise<void> {
  const server = new Server(
    { name: 'slimmcp-proxy', version: '1.0.2' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return core.handleListTools();
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    return core.handleCallTool(request.params.name, request.params.arguments);
  });

  const transport = new StdioServerTransport();
  let closed = false;
  const shutdown = async () => {
    if (closed) return;
    closed = true;
    await upstream.closeAll();
    ledger.close();
    process.exit(0);
  };

  server.onclose = () => {
    void shutdown();
  };
  process.stdin.on('end', () => {
    void shutdown();
  });
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  await server.connect(transport);
}
