import { existsSync, readFileSync } from 'node:fs';

function resolvePackageVersion(): string {
  const candidates = [
    new URL('../../package.json', import.meta.url),
    new URL('../package.json', import.meta.url)
  ];
  for (const url of candidates) {
    try {
      if (existsSync(url)) {
        const pkg = JSON.parse(readFileSync(url, 'utf8')) as { version?: string };
        if (typeof pkg.version === 'string' && pkg.version.length > 0) {
          return pkg.version;
        }
      }
    } catch {
      // Try next candidate
    }
  }
  return '1.0.2';
}

export const SLIMMCP_VERSION = resolvePackageVersion();
