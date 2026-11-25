import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { StatsSummary } from './types.js';

export type EventStatus = 'allowed' | 'blocked_policy' | 'blocked_cap' | 'error';

/**
 * Pure Node v24 built-in `node:sqlite` metrics ledger (zero native C++ addons).
 */
export class MetricsLedger {
  private db: DatabaseSync;

  constructor(dbPath: string = ':memory:') {
    if (dbPath !== ':memory:') {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    if (dbPath !== ':memory:') {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        raw_tools_count INTEGER NOT NULL,
        raw_schema_bytes INTEGER NOT NULL,
        raw_schema_tokens INTEGER NOT NULL,
        slim_exposed_bytes INTEGER NOT NULL,
        slim_exposed_tokens INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tool_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        ts TEXT NOT NULL,
        kind TEXT NOT NULL,
        server_id TEXT,
        tool_name TEXT,
        tokens_saved INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        latency_ms REAL NOT NULL DEFAULT 0,
        redactions_count INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  startSession(baseline: {
    rawToolsCount: number;
    rawSchemaBytes: number;
    rawSchemaTokens: number;
    slimExposedBytes: number;
    slimExposedTokens: number;
  }): number {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (
        started_at, raw_tools_count, raw_schema_bytes, raw_schema_tokens,
        slim_exposed_bytes, slim_exposed_tokens
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      new Date().toISOString(),
      baseline.rawToolsCount,
      baseline.rawSchemaBytes,
      baseline.rawSchemaTokens,
      baseline.slimExposedBytes,
      baseline.slimExposedTokens
    );
    return Number(result.lastInsertRowid);
  }

  recordEvent(event: {
    sessionId: number;
    kind: 'discover_tools' | 'inspect_tool_schema' | 'invoke_tool';
    serverId?: string;
    toolName?: string;
    tokensSaved?: number;
    status: EventStatus;
    latencyMs: number;
    redactionsCount?: number;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO tool_events (
        session_id, ts, kind, server_id, tool_name,
        tokens_saved, status, latency_ms, redactions_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      event.sessionId,
      new Date().toISOString(),
      event.kind,
      event.serverId ?? null,
      event.toolName ?? null,
      event.tokensSaved ?? 0,
      event.status,
      Number(event.latencyMs.toFixed(2)),
      event.redactionsCount ?? 0
    );
  }

  getStats(): StatsSummary {
    const sessAgg = this.db
      .prepare(`SELECT COUNT(*) as cnt FROM sessions`)
      .get() as { cnt: number };
    const latestSess = this.db
      .prepare(`
        SELECT raw_schema_bytes, raw_schema_tokens, slim_exposed_bytes, slim_exposed_tokens
        FROM sessions ORDER BY id DESC LIMIT 1
      `)
      .get() as
      | {
          raw_schema_bytes: number;
          raw_schema_tokens: number;
          slim_exposed_bytes: number;
          slim_exposed_tokens: number;
        }
      | undefined;

    const evAgg = this.db
      .prepare(`
        SELECT
          COUNT(*) as total_events,
          SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_calls,
          SUM(CASE WHEN status = 'blocked_policy' THEN 1 ELSE 0 END) as blocked_policy,
          SUM(CASE WHEN status = 'blocked_cap' THEN 1 ELSE 0 END) as blocked_cap,
          COALESCE(SUM(redactions_count), 0) as total_redactions,
          COALESCE(SUM(tokens_saved), 0) as cumulative_tokens_saved,
          COALESCE(AVG(latency_ms), 0) as avg_latency_ms
        FROM tool_events
      `)
      .get() as {
      total_events: number;
      allowed_calls: number | null;
      blocked_policy: number | null;
      blocked_cap: number | null;
      total_redactions: number;
      cumulative_tokens_saved: number;
      avg_latency_ms: number;
    };

    const rawTok = latestSess?.raw_schema_tokens ?? 0;
    const slimTok = latestSess?.slim_exposed_tokens ?? 0;
    const reductionPct =
      rawTok > 0 ? Number((((rawTok - slimTok) / rawTok) * 100).toFixed(2)) : 0;

    return {
      sessionsCount: sessAgg.cnt,
      totalEvents: evAgg.total_events,
      allowedCalls: evAgg.allowed_calls ?? 0,
      blockedPolicyCalls: evAgg.blocked_policy ?? 0,
      blockedCapCalls: evAgg.blocked_cap ?? 0,
      totalRedactions: evAgg.total_redactions,
      latestRawSchemaBytes: latestSess?.raw_schema_bytes ?? 0,
      latestRawSchemaTokens: rawTok,
      latestSlimExposedBytes: latestSess?.slim_exposed_bytes ?? 0,
      latestSlimExposedTokens: slimTok,
      latestReductionPercent: reductionPct,
      cumulativeTokensSaved: evAgg.cumulative_tokens_saved,
      avgLatencyMs: Number(evAgg.avg_latency_ms.toFixed(2))
    };
  }

  close(): void {
    this.db.close();
  }
}
