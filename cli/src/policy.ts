import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { PolicyConfig, PolicyRule } from './types.js';

const PolicyRuleSchema = z
  .object({
    pattern: z.string().min(1),
    action: z.enum(['allow', 'deny']),
    maxCallsPerSession: z.number().int().positive().optional(),
    estimatedX402AtomicUsdc: z.number().int().nonnegative().optional()
  })
  .strict();

export const PolicyConfigSchema = z
  .object({
    defaultAction: z.enum(['allow', 'deny']).default('allow'),
    sessionLimits: z
      .object({
        maxCallsPerSession: z.number().int().positive().optional(),
        maxX402AtomicUsdcPerSession: z.number().int().nonnegative().optional()
      })
      .strict()
      .optional(),
    rules: z.array(PolicyRuleSchema).optional()
  })
  .strict();

export function loadPolicyFile(filePath: string): PolicyConfig {
  const raw = JSON.parse(readFileSync(filePath, 'utf8')) as unknown;
  return PolicyConfigSchema.parse(raw);
}

/**
 * Case-insensitive linear-time glob matcher supporting `*` wildcards.
 * Avoids regex construction (eliminating ReDoS and unescaped regex metacharacters like `?`).
 */
export function globMatch(pattern: string, target: string): boolean {
  const p = pattern.toLowerCase();
  const t = target.toLowerCase();
  let pi = 0;
  let ti = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (ti < t.length) {
    if (pi < p.length && p[pi] === t[ti]) {
      pi += 1;
      ti += 1;
    } else if (pi < p.length && p[pi] === '*') {
      starIdx = pi;
      matchIdx = ti;
      pi += 1;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx += 1;
      ti = matchIdx;
    } else {
      return false;
    }
  }

  while (pi < p.length && p[pi] === '*') {
    pi += 1;
  }

  return pi === p.length;
}

export interface PolicyDecision {
  allowed: boolean;
  code: 'ALLOWED' | 'DENIED_BY_POLICY' | 'SESSION_CALL_CAP' | 'TOOL_CALL_CAP' | 'X402_BUDGET_CAP';
  reason?: string;
}

/**
 * Enforces MIT-free RBAC rules (strict deny-overrides precedence) and per-session call / x402 USDC spend caps.
 */
export class PolicyGuard {
  private policy: PolicyConfig | null;
  private sessionCalls = 0;
  private sessionX402AtomicUsdc = 0;
  private toolCalls = new Map<string, number>();

  constructor(policy: PolicyConfig | null) {
    this.policy = policy;
  }

  getRemainingState() {
    return {
      sessionCalls: this.sessionCalls,
      sessionX402AtomicUsdc: this.sessionX402AtomicUsdc
    };
  }

  evaluate(serverId: string, toolName: string): PolicyDecision {
    if (!this.policy) {
      return { allowed: true, code: 'ALLOWED' };
    }

    const fullKey = `${serverId}:${toolName}`;
    const matchingRules: PolicyRule[] = (this.policy.rules ?? []).filter((r) =>
      r.pattern.includes(':')
        ? globMatch(r.pattern, fullKey)
        : globMatch(r.pattern, fullKey) || globMatch(r.pattern, toolName)
    );

    // Strict deny-overrides: any matching deny rule takes precedence over allow rules regardless of ordering
    const denyRule = matchingRules.find((r) => r.action === 'deny');
    if (denyRule) {
      return {
        allowed: false,
        code: 'DENIED_BY_POLICY',
        reason: `Tool "${fullKey}" blocked by policy rule (${denyRule.pattern}).`
      };
    }

    const allowRules = matchingRules.filter((r) => r.action === 'allow');
    const action = allowRules.length > 0 ? 'allow' : this.policy.defaultAction;
    if (action === 'deny') {
      return {
        allowed: false,
        code: 'DENIED_BY_POLICY',
        reason: `Tool "${fullKey}" blocked by policy rule (defaultAction: deny).`
      };
    }

    const maxSession = this.policy.sessionLimits?.maxCallsPerSession;
    if (maxSession !== undefined && this.sessionCalls >= maxSession) {
      return {
        allowed: false,
        code: 'SESSION_CALL_CAP',
        reason: `Session call cap reached (${this.sessionCalls}/${maxSession}).`
      };
    }

    // Aggregate strictest limits across ALL matching allow rules
    const toolCallCaps = allowRules
      .map((r) => r.maxCallsPerSession)
      .filter((v): v is number => v !== undefined);
    const strictestToolCallCap =
      toolCallCaps.length > 0 ? Math.min(...toolCallCaps) : undefined;

    const prevToolCalls = this.toolCalls.get(fullKey) ?? 0;
    if (
      strictestToolCallCap !== undefined &&
      prevToolCalls >= strictestToolCallCap
    ) {
      return {
        allowed: false,
        code: 'TOOL_CALL_CAP',
        reason: `Per-tool call cap reached for "${fullKey}" (${prevToolCalls}/${strictestToolCallCap}).`
      };
    }

    const estCosts = allowRules
      .map((r) => r.estimatedX402AtomicUsdc)
      .filter((v): v is number => v !== undefined);
    const estCost = estCosts.length > 0 ? Math.max(...estCosts) : 0;
    const maxBudget = this.policy.sessionLimits?.maxX402AtomicUsdcPerSession;
    if (
      maxBudget !== undefined &&
      estCost > 0 &&
      this.sessionX402AtomicUsdc + estCost > maxBudget
    ) {
      return {
        allowed: false,
        code: 'X402_BUDGET_CAP',
        reason: `Session x402 USDC spend cap exceeded (${this.sessionX402AtomicUsdc + estCost} > ${maxBudget} atomic units).`
      };
    }

    this.sessionCalls += 1;
    this.toolCalls.set(fullKey, prevToolCalls + 1);
    this.sessionX402AtomicUsdc += estCost;

    return { allowed: true, code: 'ALLOWED' };
  }
}
