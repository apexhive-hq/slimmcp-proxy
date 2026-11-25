import { compactToolSummary, countUtf8Bytes, estimateTokens } from './tokenizer.js';
import type { IndexedTool, RawMcpTool, ToolMatch } from './types.js';

const K1 = 1.5;
const B = 0.75;

export function tokenizeTerms(text: string): string[] {
  // Split camelCase, PascalCase, snake_case, kebab-case, colons, dots, and whitespace
  const expanded = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_\-.:/]+/g, ' ')
    .toLowerCase();
  return expanded
    .split(/[^a-z0-9]+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2);
}

interface DocEntry {
  tool: IndexedTool;
  tf: Map<string, number>;
  length: number;
}

/**
 * Pure-TS deterministic BM25 progressive tool indexer.
 * Zero native dependencies or external embedding calls.
 */
export class ToolIndexer {
  private docs: DocEntry[] = [];
  private df = new Map<string, number>();
  private avgDocLen = 1;
  private byKey = new Map<string, IndexedTool>();

  rebuild(serverTools: Array<{ serverId: string; tools: RawMcpTool[] }>): IndexedTool[] {
    this.docs = [];
    this.df.clear();
    this.byKey.clear();

    let totalLen = 0;
    for (const entry of serverTools) {
      for (const raw of entry.tools) {
        const inputSchema = raw.inputSchema ?? { type: 'object', properties: {} };
        const { summary, requiredArgs, optionalArgCount } = compactToolSummary(
          raw.description,
          inputSchema
        );
        const rawBytes = countUtf8Bytes(raw);
        const rawTokens = estimateTokens(raw);
        const key = `${entry.serverId}:${raw.name}`;

        const indexed: IndexedTool = {
          key,
          serverId: entry.serverId,
          name: raw.name,
          description: raw.description ?? '',
          summary,
          requiredArgs,
          optionalArgCount,
          inputSchema,
          rawBytes,
          rawTokens
        };
        this.byKey.set(key, indexed);

        const propNames =
          typeof inputSchema.properties === 'object' && inputSchema.properties !== null
            ? Object.keys(inputSchema.properties as Record<string, unknown>).join(' ')
            : '';

        // Weight tool name & server id higher by repeating once in indexed corpus
        const corpus = `${entry.serverId} ${raw.name} ${raw.name} ${raw.description ?? ''} ${propNames}`;
        const terms = tokenizeTerms(corpus);
        const tf = new Map<string, number>();
        for (const term of terms) {
          tf.set(term, (tf.get(term) ?? 0) + 1);
        }
        for (const uniqueTerm of tf.keys()) {
          this.df.set(uniqueTerm, (this.df.get(uniqueTerm) ?? 0) + 1);
        }
        totalLen += terms.length;
        this.docs.push({ tool: indexed, tf, length: Math.max(1, terms.length) });
      }
    }

    this.avgDocLen = this.docs.length > 0 ? totalLen / this.docs.length : 1;
    return this.getAllTools();
  }

  getAllTools(): IndexedTool[] {
    return this.docs.map((d) => d.tool);
  }

  getTool(serverId: string, toolName: string): IndexedTool | undefined {
    return this.byKey.get(`${serverId}:${toolName}`);
  }

  search(query: string, options?: { server?: string; limit?: number }): ToolMatch[] {
    const limit = Math.max(1, Math.min(options?.limit ?? 8, 25));
    const serverFilter = options?.server?.trim().toLowerCase();
    const trimmed = query.trim();

    const filteredDocs = serverFilter
      ? this.docs.filter((d) => d.tool.serverId.toLowerCase() === serverFilter)
      : this.docs;

    if (!trimmed || trimmed === '*') {
      return filteredDocs.slice(0, limit).map((d) => ({
        server: d.tool.serverId,
        tool: d.tool.name,
        summary: d.tool.summary,
        requiredArgs: d.tool.requiredArgs,
        optionalArgCount: d.tool.optionalArgCount,
        score: 1
      }));
    }

    const qTerms = tokenizeTerms(trimmed);
    const qLower = trimmed.toLowerCase();
    const N = Math.max(1, this.docs.length);

    const scored: ToolMatch[] = [];
    for (const doc of filteredDocs) {
      let score = 0;
      for (const term of qTerms) {
        const freq = doc.tf.get(term) ?? 0;
        if (freq === 0) continue;
        const docFreq = this.df.get(term) ?? 0;
        const idf = Math.log(1 + (N - docFreq + 0.5) / (docFreq + 0.5));
        const tfNorm =
          (freq * (K1 + 1)) /
          (freq + K1 * (1 - B + B * (doc.length / Math.max(1, this.avgDocLen))));
        score += idf * tfNorm;
      }

      const nameLower = doc.tool.name.toLowerCase();
      const keyLower = doc.tool.key.toLowerCase();
      if (nameLower === qLower || keyLower === qLower) {
        score += 10;
      } else if (nameLower.includes(qLower)) {
        score += 3;
      }

      if (score > 0) {
        scored.push({
          server: doc.tool.serverId,
          tool: doc.tool.name,
          summary: doc.tool.summary,
          requiredArgs: doc.tool.requiredArgs,
          optionalArgCount: doc.tool.optionalArgCount,
          score: Number(score.toFixed(4))
        });
      }
    }

    scored.sort((a, b) => b.score - a.score || a.tool.localeCompare(b.tool));
    return scored.slice(0, limit);
  }
}
