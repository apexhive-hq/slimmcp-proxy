export interface UpstreamServerConfig {
  id: string;
  transport?: 'stdio' | 'streamable-http' | 'sse';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  headers?: Record<string, string>;
}

export interface SlimMcpConfig {
  servers: UpstreamServerConfig[];
  redaction?: {
    enabled?: boolean;
    redactInputs?: boolean;
    redactOutputs?: boolean;
  };
}

export interface RawMcpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface IndexedTool {
  key: string; // `${serverId}:${toolName}`
  serverId: string;
  name: string;
  description: string;
  summary: string;
  requiredArgs: string[];
  optionalArgCount: number;
  inputSchema: Record<string, unknown>;
  rawBytes: number;
  rawTokens: number;
}

export interface ToolMatch {
  server: string;
  tool: string;
  summary: string;
  requiredArgs: string[];
  optionalArgCount: number;
  score: number;
}

export interface PolicyRule {
  pattern: string;
  action: 'allow' | 'deny';
  maxCallsPerSession?: number;
  estimatedX402AtomicUsdc?: number;
}

export interface PolicyConfig {
  defaultAction: 'allow' | 'deny';
  sessionLimits?: {
    maxCallsPerSession?: number;
    maxX402AtomicUsdcPerSession?: number;
  };
  rules?: PolicyRule[];
}

export interface RedactionResult<T = unknown> {
  sanitized: T;
  redactionCount: number;
  matchedRules: string[];
}

export interface StatsSummary {
  sessionsCount: number;
  totalEvents: number;
  allowedCalls: number;
  blockedPolicyCalls: number;
  blockedCapCalls: number;
  totalRedactions: number;
  latestRawSchemaBytes: number;
  latestRawSchemaTokens: number;
  latestSlimExposedBytes: number;
  latestSlimExposedTokens: number;
  latestReductionPercent: number;
  cumulativeTokensSaved: number;
  avgLatencyMs: number;
}
