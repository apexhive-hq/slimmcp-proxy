import { createPublicKey, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import type { LicenseVerificationResult, ProLicensePayload } from './types.js';

/**
 * Production SPKI Ed25519 public key for ApexHive Labs Pro license verification.
 * Override at runtime via SLIMMCP_PUBLIC_KEY or pass explicit publicKeySpkiB64 in tests.
 * Zero private keys ever ship inside this open-source CLI package.
 */
export const DEFAULT_APEXHIVE_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAtQL6JGroxnMwecs/H+qPnGs6QQQnryQzkw26HrttLfM=';

const TOKEN_PREFIX = 'APEXHIVE-PRO-v1.';

const LicensePayloadSchema = z.object({
  v: z.literal(1),
  product: z.literal('slimmcp-proxy'),
  tier: z.enum(['indie', 'team']),
  payer: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  issuedAt: z.number().int().positive(),
  expiresAt: z.number().int().positive().nullable()
});

function toPublicKeyObject(spkiB64: string) {
  const der = Buffer.from(spkiB64.trim(), 'base64');
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

export function verifyProLicenseToken(
  token: string,
  options?: { publicKeySpkiB64?: string; nowMs?: number }
): LicenseVerificationResult {
  const trimmed = token.trim();
  if (!trimmed.startsWith(TOKEN_PREFIX)) {
    return { valid: false, reason: 'Invalid license token prefix (expected APEXHIVE-PRO-v1).' };
  }

  const parts = trimmed.slice(TOKEN_PREFIX.length).split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, reason: 'Malformed license token structure.' };
  }

  const [payloadB64Url, sigB64Url] = parts;
  const spkiB64 =
    options?.publicKeySpkiB64 ||
    process.env.SLIMMCP_PUBLIC_KEY ||
    DEFAULT_APEXHIVE_PUBLIC_KEY_SPKI_B64;

  let sigVerified = false;
  try {
    const pubKey = toPublicKeyObject(spkiB64);
    const signingInput = Buffer.from(`${TOKEN_PREFIX}${payloadB64Url}`, 'utf8');
    const sigBytes = Buffer.from(sigB64Url, 'base64url');
    sigVerified = verify(null, signingInput, pubKey, sigBytes);
  } catch (err) {
    return {
      valid: false,
      reason: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`
    };
  }

  if (!sigVerified) {
    return { valid: false, reason: 'Invalid Ed25519 signature.' };
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(Buffer.from(payloadB64Url, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'Malformed JSON payload in license token.' };
  }

  const parsed = LicensePayloadSchema.safeParse(parsedJson);
  if (!parsed.success) {
    return { valid: false, reason: `Invalid license payload fields: ${parsed.error.message}` };
  }

  const payload: ProLicensePayload = parsed.data;
  const now = options?.nowMs ?? Date.now();
  if (payload.expiresAt !== null && now > payload.expiresAt) {
    return { valid: false, reason: 'License token has expired.', payload };
  }

  return { valid: true, payload };
}

export function resolveSlimMcpHome(customHome?: string): string {
  if (customHome) return customHome;
  if (process.env.SLIMMCP_HOME) return process.env.SLIMMCP_HOME;
  const base = process.env.APPDATA || homedir();
  return join(base, '.slimmcp-proxy');
}

export function saveActivatedLicense(
  token: string,
  options?: { homeDir?: string; publicKeySpkiB64?: string }
): { filePath: string; verification: LicenseVerificationResult } {
  const verification = verifyProLicenseToken(token, {
    publicKeySpkiB64: options?.publicKeySpkiB64
  });
  if (!verification.valid) {
    throw new Error(verification.reason || 'License verification failed.');
  }
  const home = resolveSlimMcpHome(options?.homeDir);
  mkdirSync(home, { recursive: true });
  const filePath = join(home, 'license.json');
  writeFileSync(
    filePath,
    JSON.stringify(
      {
        token: token.trim(),
        activatedAt: new Date().toISOString(),
        payload: verification.payload
      },
      null,
      2
    ),
    'utf8'
  );
  return { filePath, verification };
}

export function loadActivatedLicense(options?: {
  homeDir?: string;
  publicKeySpkiB64?: string;
}): LicenseVerificationResult {
  const envToken = process.env.SLIMMCP_LICENSE_TOKEN;
  if (envToken) {
    return verifyProLicenseToken(envToken, {
      publicKeySpkiB64: options?.publicKeySpkiB64
    });
  }

  const home = resolveSlimMcpHome(options?.homeDir);
  const filePath = join(home, 'license.json');
  if (!existsSync(filePath)) {
    return { valid: false, reason: 'No activated Pro license found.' };
  }

  try {
    const raw = JSON.parse(readFileSync(filePath, 'utf8')) as { token?: string };
    if (!raw.token) {
      return { valid: false, reason: 'Corrupted license.json (missing token).' };
    }
    return verifyProLicenseToken(raw.token, {
      publicKeySpkiB64: options?.publicKeySpkiB64
    });
  } catch (err) {
    return {
      valid: false,
      reason: `Failed to read license.json: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}
