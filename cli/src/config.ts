import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { SlimMcpConfig, UpstreamServerConfig } from './types.js';

const UpstreamServerSchema = z.object({
  id: z.string().min(1),
  command: z.string().min(1),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  cwd: z.string().optional()
});

const NativeConfigSchema = z.object({
  servers: z.array(UpstreamServerSchema).min(1),
  redaction: z
    .object({
      enabled: z.boolean().optional(),
      redactInputs: z.boolean().optional(),
      redactOutputs: z.boolean().optional()
    })
    .optional()
});

const ClaudeStyleConfigSchema = z.object({
  mcpServers: z.record(
    z.object({
      command: z.string().min(1),
      args: z.array(z.string()).optional(),
      env: z.record(z.string()).optional(),
      cwd: z.string().optional()
    })
  ),
  redaction: z
    .object({
      enabled: z.boolean().optional(),
      redactInputs: z.boolean().optional(),
      redactOutputs: z.boolean().optional()
    })
    .optional()
});

/**
 * Loads either native `{ servers: [...] }` config or standard Claude/Cursor `{ mcpServers: { id: {...} } }` JSON.
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
        command: srv.command,
        args: srv.args,
        env: srv.env,
        cwd: srv.cwd
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
