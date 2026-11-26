import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { SlimMcpConfig, UpstreamServerConfig } from './types.js';
import { validateUpstreamUrl } from './upstream.js';

const ServerEndpointFields = {
  transport: z.enum(['stdio', 'streamable-http', 'sse']).optional(),
  command: z.string().min(1).optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  envAllowlist: z.array(z.string().min(1)).optional(),
  cwd: z.string().optional(),
  url: z
    .string()
    .url()
    .refine(
      (u) => {
        try {
          validateUpstreamUrl(u);
          return true;
        } catch {
          return false;
        }
      },
      { message: 'Upstream url must use http: or https: and must not target cloud metadata endpoints.' }
    )
    .optional(),
  headers: z.record(z.string()).optional(),
  connectTimeoutMs: z.number().int().positive().optional(),
  requestTimeoutMs: z.number().int().positive().optional()
};

function hasValidTransport(s: { command?: string; url?: string }): boolean {
  return Boolean(s.command || s.url);
}

const UpstreamServerSchema = z
  .object({
    id: z.string().min(1),
    ...ServerEndpointFields
  })
  .refine(hasValidTransport, { message: 'Each upstream server must specify either "command" (stdio) or "url" (HTTP/SSE).' });

const ClaudeServerEntrySchema = z
  .object(ServerEndpointFields)
  .refine(hasValidTransport, { message: 'Each mcpServers entry must specify either "command" or "url".' });

const RedactionSchema = z
  .object({
    enabled: z.boolean().optional(),
    redactInputs: z.boolean().optional(),
    redactOutputs: z.boolean().optional()
  })
  .optional();

const NativeConfigSchema = z.object({
  servers: z.array(UpstreamServerSchema).min(1),
  redaction: RedactionSchema
});

const ClaudeStyleConfigSchema = z.object({
  mcpServers: z.record(ClaudeServerEntrySchema),
  redaction: RedactionSchema
});

/**
 * Loads either native `{ servers: [...] }` config or standard Claude/Cursor `{ mcpServers: { id: {...} } }` JSON,
 * supporting both stdio (`command`) and remote Streamable-HTTP / SSE (`url`) upstreams.
 */
export function loadSlimMcpConfig(filePath: string): SlimMcpConfig {
  const raw = JSON.parse(readFileSync(filePath, 'utf8')) as unknown;

  const nativeParsed = NativeConfigSchema.safeParse(raw);
  if (nativeParsed.success) {
    return nativeParsed.data;
  }

  const claudeParsed = ClaudeStyleConfigSchema.safeParse(raw);
  if (claudeParsed.success) {
    const servers: UpstreamServerConfig[] = Object.entries(claudeParsed.data.mcpServers).map(
      ([id, srv]) => ({
        id,
        ...srv
      })
    );
    if (servers.length === 0) {
      throw new Error('mcpServers map cannot be empty.');
    }
    return {
      servers,
      redaction: claudeParsed.data.redaction
    };
  }

  throw new Error(
    `Invalid SlimMCP config in "${filePath}": ${nativeParsed.error.message}`
  );
}
