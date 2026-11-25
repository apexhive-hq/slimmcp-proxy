import type { RedactionResult } from './types.js';

interface SecretPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'pem_private_key',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: '[REDACTED:PRIVATE_KEY]'
  },
  {
    name: 'aws_access_key',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED:AWS_KEY]'
  },
  {
    name: 'github_pat_fine',
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    replacement: '[REDACTED:GITHUB_PAT]'
  },
  {
    name: 'github_token',
    regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    replacement: '[REDACTED:GITHUB_TOKEN]'
  },
  {
    name: 'stripe_live_key',
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,
    replacement: '[REDACTED:STRIPE_KEY]'
  },
  {
    name: 'openai_anthropic_key',
    regex: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
    replacement: '[REDACTED:API_KEY]'
  },
  {
    name: 'slack_token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    replacement: '[REDACTED:SLACK_TOKEN]'
  },
  {
    name: 'jwt_token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: '[REDACTED:JWT]'
  },
  {
    name: 'evm_hex_private_key_assignment',
    regex: /\b(private[_-]?key|secret[_-]?key|mnemonic)\s*[:=]\s*["']?(?:0x)?[0-9a-fA-F]{64}["']?/gi,
    replacement: '$1=[REDACTED:SECRET_KEY]'
  }
];

function redactString(
  input: string,
  matchedRules: Set<string>
): { text: string; count: number } {
  let text = input;
  let count = 0;
  for (const rule of SECRET_PATTERNS) {
    rule.regex.lastIndex = 0;
    const matches = text.match(rule.regex);
    if (matches && matches.length > 0) {
      count += matches.length;
      matchedRules.add(rule.name);
      text = text.replace(rule.regex, rule.replacement);
    }
  }
  return { text, count };
}

export function redactSecrets<T>(value: T): RedactionResult<T> {
  const matchedRules = new Set<string>();
  const seen = new WeakSet<object>();
  let redactionCount = 0;

  function walk(node: unknown, depth: number): unknown {
    if (depth > 24 || node === null || node === undefined) return node;
    if (typeof node === 'string') {
      const res = redactString(node, matchedRules);
      redactionCount += res.count;
      return res.text;
    }
    if (typeof node !== 'object') return node;
    if (seen.has(node as object)) return '[Circular]';
    seen.add(node as object);

    if (Array.isArray(node)) {
      return node.map((item) => walk(item, depth + 1));
    }

    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = walk(v, depth + 1);
    }
    return out;
  }

  const sanitized = walk(value, 0) as T;
  return {
    sanitized,
    redactionCount,
    matchedRules: Array.from(matchedRules)
  };
}
