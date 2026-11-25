import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { PolicyConfig, PolicyRule } from './types.js';

const PolicyRuleSchema = z.object({
  pattern: z.string().min(1),
  action: z.enum(['allow', 'deny']),
  maxCallsPerSession: z.number().int().positive().optional(),
  estimatedX402AtomicUsdc: z.number().int().nonnegative().optional()
});

export const PolicyConfigSchema = z.object({
  defaultAction: z.enum(['allow', 'deny']).default('allow'),
  sessionLimits: z
    .object({
      maxCallsPerSession: z.number().int().positive().optional(),
      maxX402AtomicUsdcPerSession: z.number().int().nonnegative().optional()
    })
    .optional(),
  rules: z.array(PolicyRuleSchema).optional()
});

export function loadPolicyFile(filePath: string): PolicyConfig {
  const raw = JSON.parse(readFileSync(filePath, 'utf8')) as unknown;
  return PolicyConfigSchema.parse(raw);
}

function globMatch(pattern: string, target: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(target);
}

export interface PolicyDecision {
  allowed: boolean;
  code: 'ALLOWED' | 'PRO_LICENSE_REQUIRED' | 'DENIED_BY_POLICY' | 'SESSION_CALL_CAP' | 'TOOL_CALL_CAP' | 'X402_BUDGET_CAP';
  reason?: string;
}

/**
 * Enforces Pro-tier RBAC rules and per-session call / x402 USDC spend caps.
 */
export class PolicyGuard {
  private policy: PolicyConfig | null;
  private isProActive: boolean;
  private sessionCalls = 0;
  private sessionX402AtomicUsdc = 0;
  private toolCalls = new Map<string, number>();

  constructor(policy: PolicyConfig | null, isProActive: boolean) {
    this.policy = policy;
    this.isProActive = isProActive;
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

    if (!this.isProActive) {
      return {
        allowed: false,
        code: 'PRO_LICENSE_REQUIRED',
        reason:
          'Custom slimmcp.policy.json RBAC & spend-cap rules require an active ApexHive Labs Pro license (5 USDC Founding Batch on Base). Run `node dist/src/cli.js activate --token <TOKEN>` or remove --policy for Free Open-Core mode.'
      };
    }

    const fullKey = `${serverId}:${toolName}`;
    const matchedRule: PolicyRule | undefined = (this.policy.rules ?? []).find(
      (r) => globMatch(r.pattern, fullKey) || globMatch(r.pattern, toolName)
    );

    const action = matchedRule?.action ?? this.policy.defaultAction;
    if (action === 'deny') {
      return {
        allowed: false,
        code: 'DENIED_BY_POLICY',
        reason: `Tool "${fullKey}" blocked by policy rule (${matchedRule ? matchedRule.pattern : 'defaultAction: deny'}).`
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

    const prevToolCalls = this.toolCalls.get(fullKey) ?? 0;
    if (
      matchedRule?.maxCallsPerSession !== undefined &&
      prevToolCalls >= matchedRule.maxCallsPerSession
    ) {
      return {
        allowed: false,
        code: 'TOOL_CALL_CAP',
        reason: `Per-tool call cap reached for "${fullKey}" (${prevToolCalls}/${matchedRule.maxCallsPerSession}).`
      };
    }

    const estCost = matchedRule?.estimatedX402AtomicUsdc ?? 0;
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
