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
    name: 'gitlab_pat',
    regex: /\bglpat-[0-9A-Za-z_-]{20,}\b/g,
    replacement: '[REDACTED:GITLAB_PAT]'
  },
  {
    name: 'npm_token',
    regex: /\bnpm_[A-Za-z0-9]{20,}\b/g,
    replacement: '[REDACTED:NPM_TOKEN]'
  },
  {
    name: 'huggingface_token',
    regex: /\bhf_[A-Za-z0-9]{20,}\b/g,
    replacement: '[REDACTED:HF_TOKEN]'
  },
  {
    name: 'google_api_key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replacement: '[REDACTED:GCP_API_KEY]'
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
    name: 'bearer_token',
    regex: /\bBearer\s+(?=[A-Za-z0-9._~+/-]{20,})(?=[A-Za-z0-9._~+/-]*[0-9_-])[A-Za-z0-9._~+/-]{20,}=*/gi,
    replacement: 'Bearer [REDACTED:BEARER_TOKEN]'
  },
  {
    name: 'url_credentials',
    regex: /\b((?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|ftps?|mssql|cockroachdb):\/\/[^:\s/@"']+:)(?!\[REDACTED:)[^@\s/"']+(@)/gi,
    replacement: '$1[REDACTED:PASSWORD]$2'
  },
  {
    name: 'evm_hex_private_key_assignment',
    regex: /\b(private[_-]?key|secret[_-]?key|mnemonic)(["']?\s*[:=]\s*["']?)(?:0x)?[0-9a-fA-F]{64}(["']?)/gi,
    replacement: '$1$2[REDACTED:SECRET_KEY]$3'
  },
  {
    name: 'mnemonic_seed_assignment',
    regex: /\b(mnemonic|seed[_-]?phrase|recovery[_-]?phrase)(["']?\s*[:=]\s*["']?)(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}(["']?)/gi,
    replacement: '$1$2[REDACTED:MNEMONIC]$3'
  },
  {
    name: 'secret_assignment',
    regex: /\b(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)(["']?\s*[:=]\s*["']?)(?!\[REDACTED:|[{[])(?!(?:string|number|boolean|object|array|null|undefined|true|false|required|optional)\b)([^\s"',;}&]{8,})(["']?)/gi,
    replacement: '$1$2[REDACTED:SECRET]$4'
  }
];

const MAX_WALK_DEPTH = 24;

const METADATA_SUFFIX_WORDS = new Set([
  'count',
  'counts',
  'limit',
  'limits',
  'max',
  'min',
  'length',
  'len',
  'size',
  'age',
  'ttl',
  'expiry',
  'expires',
  'saved',
  'usage',
  'budget',
  'enabled',
  'disabled',
  'required',
  'optional'
]);

const NUMERIC_TOKEN_METRIC_PREFIXES = new Set([
  'schema',
  'slim',
  'exposed',
  'discover',
  'inspect',
  'prompt',
  'completion',
  'input',
  'output',
  'total',
  'max',
  'min',
  'used',
  'remaining',
  'estimated',
  'cumulative'
]);

const SENSITIVE_SINGLE_WORDS = new Set([
  'secret',
  'secrets',
  'password',
  'passwords',
  'passwd',
  'passphrase',
  'mnemonic',
  'mnemonics',
  'authorization',
  'cookie',
  'cookies',
  'credential',
  'credentials',
  'apikey',
  'apikeys',
  'privatekey',
  'privatekeys',
  'secretkey',
  'secretkeys',
  'accesstoken',
  'authtoken',
  'refreshtoken',
  'bearertoken',
  'idtoken',
  'clientsecret',
  'setcookie',
  'seedphrase',
  'recoveryphrase'
]);

function splitKeyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function isSensitiveKey(key: string, value: unknown): boolean {
  const words = splitKeyWords(key);
  if (words.length === 0) return false;

  const last = words[words.length - 1];
  if ((typeof value === 'number' || typeof value === 'boolean') && METADATA_SUFFIX_WORDS.has(last)) {
    return false;
  }

  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (SENSITIVE_SINGLE_WORDS.has(w)) {
      return true;
    }
    if (w === 'token' || w === 'tokens') {
      const prev = i > 0 ? words[i - 1] : '';
      // Only exempt plural/count numeric LLM token metrics (e.g. maxTokens: 4096, rawSchemaTokens: 15047).
      // Any string/object/array under token/tokens (e.g. raw_token, oauth_tokens, access_tokens) is redacted.
      if (typeof value === 'number' && w === 'tokens' && NUMERIC_TOKEN_METRIC_PREFIXES.has(prev)) {
        continue;
      }
      return true;
    }
    if (i < words.length - 1) {
      const next = words[i + 1];
      if ((w === 'api' || w === 'private' || w === 'secret') && (next === 'key' || next === 'keys')) {
        return true;
      }
      if ((w === 'seed' || w === 'recovery') && next === 'phrase') {
        return true;
      }
    }
  }

  return false;
}

function setSafeOwnProperty(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true
  });
}

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
    if (depth > MAX_WALK_DEPTH) {
      redactionCount += 1;
      matchedRules.add('max_depth_exceeded');
      return '[REDACTED:MAX_DEPTH_EXCEEDED]';
    }
    if (node === null || node === undefined) return node;
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
      if (depth + 1 > MAX_WALK_DEPTH) {
        redactionCount += 1;
        matchedRules.add('max_depth_exceeded');
        setSafeOwnProperty(out, k, '[REDACTED:MAX_DEPTH_EXCEEDED]');
        continue;
      }

      if (v !== null && v !== undefined && typeof v !== 'boolean' && isSensitiveKey(k, v)) {
        if (typeof v === 'string') {
          if (v.length === 0) {
            setSafeOwnProperty(out, k, v);
            continue;
          }
          const res = redactString(v, matchedRules);
          if (res.count > 0 && /^\[REDACTED:[A-Z0-9_]+\]$/.test(res.text)) {
            redactionCount += res.count;
            setSafeOwnProperty(out, k, res.text);
          } else {
            redactionCount += 1;
            matchedRules.add('sensitive_key');
            setSafeOwnProperty(out, k, '[REDACTED:SENSITIVE_KEY]');
          }
          continue;
        }
        if (typeof v === 'number' || typeof v === 'bigint') {
          redactionCount += 1;
          matchedRules.add('sensitive_key');
          setSafeOwnProperty(out, k, '[REDACTED:SENSITIVE_KEY]');
          continue;
        }
        if (typeof v === 'object') {
          redactionCount += 1;
          matchedRules.add('sensitive_key');
          setSafeOwnProperty(out, k, '[REDACTED:SENSITIVE_KEY]');
          continue;
        }
      }

      setSafeOwnProperty(out, k, walk(v, depth + 1));
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
