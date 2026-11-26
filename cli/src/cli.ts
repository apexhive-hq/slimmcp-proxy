#!/usr/bin/env node
import { join } from 'node:path';
import { loadSlimMcpConfig } from './config.js';
import { ToolIndexer } from './indexer.js';
import { MetricsLedger } from './ledger.js';
import { loadPolicyFile, PolicyGuard } from './policy.js';
import {
  computeSchemaSavings,
  SlimProxyCore,
  startStdioProxyServer
} from './server.js';
import { countUtf8Bytes, estimateTokens } from './tokenizer.js';
import { UpstreamManager } from './upstream.js';
import { SLIMMCP_VERSION } from './version.js';

function resolveSlimMcpHome(): string {
  const envHome = process.env.SLIMMCP_HOME?.trim();
  if (envHome) return envHome;
  const baseHome = process.env.HOME || process.env.USERPROFILE || process.cwd();
  return join(baseHome, '.slimmcp');
}

const BOOLEAN_FLAGS = new Set(['help', 'version', 'json']);

function parseFlags(argv: string[]): { cmd: string; flags: Map<string, string | boolean> } {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        flags.set(arg.slice(2, eqIdx), arg.slice(eqIdx + 1));
      } else {
        const flagName = arg.slice(2);
        const next = argv[i + 1];
        if (!BOOLEAN_FLAGS.has(flagName) && next && !next.startsWith('-')) {
          flags.set(flagName, next);
          i += 1;
        } else {
          flags.set(flagName, true);
        }
      }
    } else if (arg === '-h') {
      flags.set('help', true);
    } else if (arg === '-v' || arg === '-V') {
      flags.set('version', true);
    } else {
      positional.push(arg);
    }
  }

  return { cmd: positional[0] ?? 'help', flags };
}

function printHelp() {
  console.log(`slimmcp-proxy v${SLIMMCP_VERSION} — Free MIT Progressive-Disclosure Meta-MCP Proxy

Usage:
  slimmcp-proxy serve --config <mcp.json> [--policy <policy.json>] [--db <metrics.sqlite>] [--home <dir>]
  slimmcp-proxy benchmark --config <mcp.json> [--json]
  slimmcp-proxy stats [--db <metrics.sqlite>] [--home <dir>] [--json]
  slimmcp-proxy status
`);
}

async function runBenchmark(configPath: string, asJson: boolean) {
  const cfg = loadSlimMcpConfig(configPath);
  const upstream = new UpstreamManager();
  try {
    const t0 = performance.now();
    const serverTools = await upstream.connectAll(cfg.servers);
    const indexer = new ToolIndexer();
    indexer.rebuild(serverTools);
    const savings = computeSchemaSavings(serverTools);

    const sampleMatches = indexer.search('list', { limit: 5 });
    const discoverBytes = countUtf8Bytes(sampleMatches);
    const discoverTokens = estimateTokens(sampleMatches);
    const firstTool = sampleMatches[0]
      ? indexer.getTool(sampleMatches[0].server, sampleMatches[0].tool)
      : indexer.getAllTools()[0];
    const inspectTokens = firstTool ? estimateTokens(firstTool.inputSchema) : 0;
    const elapsedMs = Number((performance.now() - t0).toFixed(2));

    const report = {
      serversConnected: serverTools.length,
      ...savings,
      sampleTurnOverheadTokens: savings.slimExposedTokens + discoverTokens + inspectTokens,
      sampleDiscoverBytes: discoverBytes,
      sampleDiscoverTokens: discoverTokens,
      sampleInspectTokens: inspectTokens,
      benchmarkDurationMs: elapsedMs,
      tokenEstimationNote: 'Heuristic ~4 UTF-8 bytes per token; exact UTF-8 byte counts also reported.'
    };

    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`=== slimmcp-proxy Benchmark (MIT) ===`);
      console.log(`Servers connected:     ${report.serversConnected}`);
      console.log(`Upstream tools count:  ${report.rawToolsCount}`);
      console.log(
        `Raw tools/list:        ${report.rawSchemaBytes} bytes (~${report.rawSchemaTokens} tokens)`
      );
      console.log(
        `Slim proxy tools/list: ${report.slimExposedBytes} bytes (~${report.slimExposedTokens} tokens, ${report.reductionPercent}% initial reduction)`
      );
      console.log(
        `1-Turn Lookup Cost:    ~${report.sampleTurnOverheadTokens} tokens (meta-tools + 5 matches + 1 schema)`
      );
      console.log(`Duration:              ${report.benchmarkDurationMs} ms`);
    }
  } finally {
    await upstream.closeAll();
  }
}

async function main() {
  const { cmd, flags } = parseFlags(process.argv.slice(2));
  if (flags.get('version') || cmd === 'version') {
    console.log(SLIMMCP_VERSION);
    return;
  }
  if (flags.get('help') || flags.get('h') || cmd === 'help') {
    printHelp();
    return;
  }

  const homeDir =
    typeof flags.get('home') === 'string'
      ? (flags.get('home') as string)
      : resolveSlimMcpHome();
  const dbPath =
    typeof flags.get('db') === 'string'
      ? (flags.get('db') as string)
      : join(homeDir, 'metrics.sqlite');

  if (cmd === 'status') {
    console.log(
      JSON.stringify(
        {
          mode: 'open-source-mit',
          license: 'MIT',
          version: SLIMMCP_VERSION,
          homeDir,
          features: ['stdio-upstream', 'streamable-http-upstream', 'sse-upstream', 'bm25-discovery', 'secret-redaction', 'policy-guard', 'sqlite-metrics']
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd === 'stats') {
    const ledger = new MetricsLedger(dbPath);
    const stats = ledger.getStats();
    ledger.close();
    if (flags.get('json')) {
      console.log(JSON.stringify(stats, null, 2));
    } else {
      console.log(`Sessions: ${stats.sessionsCount} | Events: ${stats.totalEvents}`);
      console.log(
        `Latest schema reduction: ${stats.latestRawSchemaTokens} -> ${stats.latestSlimExposedTokens} tokens (${stats.latestReductionPercent}%)`
      );
      console.log(
        `Calls allowed: ${stats.allowedCalls} | Blocked policy: ${stats.blockedPolicyCalls} | Blocked cap: ${stats.blockedCapCalls} | Redactions: ${stats.totalRedactions}`
      );
    }
    return;
  }

  if (cmd === 'benchmark') {
    const configPath = flags.get('config');
    if (typeof configPath !== 'string' || !configPath) {
      console.error('Missing --config <path>');
      process.exit(1);
    }
    await runBenchmark(configPath, Boolean(flags.get('json')));
    return;
  }

  if (cmd === 'serve') {
    const configPath = flags.get('config');
    if (typeof configPath !== 'string' || !configPath) {
      console.error('Missing --config <path>');
      process.exit(1);
    }
    const cfg = loadSlimMcpConfig(configPath);
    const policyFlag = flags.get('policy');
    if (policyFlag !== undefined && (typeof policyFlag !== 'string' || !policyFlag.trim())) {
      console.error('Missing <path> for --policy');
      process.exit(1);
    }
    const policy = typeof policyFlag === 'string' ? loadPolicyFile(policyFlag) : null;

    const upstream = new UpstreamManager();
    const serverTools = await upstream.connectAll(cfg.servers);
    const indexer = new ToolIndexer();
    indexer.rebuild(serverTools);

    const savings = computeSchemaSavings(serverTools);
    const ledger = new MetricsLedger(dbPath);
    const sessionId = ledger.startSession({
      rawToolsCount: savings.rawToolsCount,
      rawSchemaBytes: savings.rawSchemaBytes,
      rawSchemaTokens: savings.rawSchemaTokens,
      slimExposedBytes: savings.slimExposedBytes,
      slimExposedTokens: savings.slimExposedTokens
    });

    const policyGuard = new PolicyGuard(policy);
    const core = new SlimProxyCore({
      config: cfg,
      upstream,
      indexer,
      policyGuard,
      ledger,
      sessionId
    });

    await startStdioProxyServer(core, upstream, ledger);
    return;
  }

  printHelp();
  process.exit(1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
