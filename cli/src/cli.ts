#!/usr/bin/env node
import { join } from 'node:path';
import { loadSlimMcpConfig } from './config.js';
import { ToolIndexer } from './indexer.js';
import { MetricsLedger } from './ledger.js';
import {
  loadActivatedLicense,
  resolveSlimMcpHome,
  saveActivatedLicense
} from './license.js';
import { loadPolicyFile, PolicyGuard } from './policy.js';
import {
  computeSchemaSavings,
  SlimProxyCore,
  startStdioProxyServer
} from './server.js';
import { countUtf8Bytes, estimateTokens } from './tokenizer.js';
import { UpstreamManager } from './upstream.js';

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
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
          flags.set(arg.slice(2), next);
          i += 1;
        } else {
          flags.set(arg.slice(2), true);
        }
      }
    } else {
      positional.push(arg);
    }
  }

  return { cmd: positional[0] ?? 'help', flags };
}

function printHelp() {
  console.log(`ApexHive Labs — slimmcp-proxy v1.0.0

Usage:
  slimmcp-proxy serve --config <mcp.json> [--policy <policy.json>] [--db <metrics.sqlite>] [--home <dir>]
  slimmcp-proxy benchmark --config <mcp.json> [--json]
  slimmcp-proxy activate --token <APEXHIVE-PRO-v1...> [--home <dir>] [--pubkey <spki-b64>]
  slimmcp-proxy status [--home <dir>] [--pubkey <spki-b64>]
  slimmcp-proxy stats [--db <metrics.sqlite>] [--home <dir>] [--json]
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

    // Measure realistic 1-turn progressive lookup cost (discover_tools + inspect_tool_schema)
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
      console.log(`=== ApexHive Labs slimmcp-proxy Benchmark ===`);
      console.log(`Servers connected:     ${report.serversConnected}`);
      console.log(`Upstream tools count:  ${report.rawToolsCount}`);
      console.log(
        `Raw tools/list:        ${report.rawSchemaBytes} bytes (~${report.rawSchemaTokens} tokens)`
      );
      console.log(
        `Slim proxy tools/list: ${report.slimExposedBytes} bytes (~${report.slimExposedTokens} tokens)`
      );
      console.log(
        `Context Tax Saved:     ${report.tokensSaved} tokens (${report.reductionPercent}% initial reduction)`
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
  if (flags.get('help') || cmd === 'help') {
    printHelp();
    return;
  }
  if (flags.get('version') || cmd === 'version') {
    console.log('1.0.0');
    return;
  }

  const homeDir =
    typeof flags.get('home') === 'string'
      ? (flags.get('home') as string)
      : resolveSlimMcpHome();
  const pubKey =
    typeof flags.get('pubkey') === 'string' ? (flags.get('pubkey') as string) : undefined;
  const dbPath =
    typeof flags.get('db') === 'string'
      ? (flags.get('db') as string)
      : join(homeDir, 'metrics.sqlite');

  if (cmd === 'activate') {
    const token = flags.get('token');
    if (typeof token !== 'string' || !token) {
      console.error('Missing --token <APEXHIVE-PRO-v1...>');
      process.exit(1);
    }
    const res = saveActivatedLicense(token, { homeDir, publicKeySpkiB64: pubKey });
    console.log(
      JSON.stringify(
        {
          activated: true,
          filePath: res.filePath,
          tier: res.verification.payload?.tier,
          payer: res.verification.payload?.payer,
          txHash: res.verification.payload?.txHash
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd === 'status') {
    const res = loadActivatedLicense({ homeDir, publicKeySpkiB64: pubKey });
    console.log(JSON.stringify({ homeDir, ...res }, null, 2));
    if (!res.valid) process.exit(1);
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
    const policyPath =
      typeof flags.get('policy') === 'string' ? (flags.get('policy') as string) : undefined;
    const policy = policyPath ? loadPolicyFile(policyPath) : null;
    const license = loadActivatedLicense({ homeDir, publicKeySpkiB64: pubKey });

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

    const policyGuard = new PolicyGuard(policy, license.valid);
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
