import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  computeSchemaSavings,
  MetricsLedger,
  PolicyGuard,
  redactSecrets,
  SlimProxyCore,
  ToolIndexer,
  UpstreamManager
} from '../src/index.js';

test('1. real stdio MCP proxy achieves >=85% context reduction and full progressive tool execution', async () => {
  const fixturePath = resolve(process.cwd(), 'dist/tests/fixtures/mock-mcp-server.js');
  const upstream = new UpstreamManager();
  const ledger = new MetricsLedger(':memory:');

  try {
    const serverTools = await upstream.connectAll([
      { id: 'devtools', command: 'node', args: [fixturePath, '--server=devtools', '--count=20'] },
      { id: 'cloud', command: 'node', args: [fixturePath, '--server=cloud', '--count=20'] },
      { id: 'finance', command: 'node', args: [fixturePath, '--server=finance', '--count=20'] }
    ]);

    const savings = computeSchemaSavings(serverTools);
    assert.equal(savings.rawToolsCount, 60);
    assert.equal(savings.slimToolsCount, 3);
    assert.ok(
      savings.reductionPercent >= 85,
      `Expected >=85% reduction, got ${savings.reductionPercent}%`
    );

    const indexer = new ToolIndexer();
    indexer.rebuild(serverTools);
    const sessionId = ledger.startSession(savings);
    const core = new SlimProxyCore({
      config: { servers: [], redaction: { enabled: true, redactInputs: true, redactOutputs: true } },
      upstream,
      indexer,
      policyGuard: new PolicyGuard(null),
      ledger,
      sessionId
    });

    const listRes = await core.handleListTools();
    assert.deepEqual(
      listRes.tools.map((t) => t.name),
      ['discover_tools', 'inspect_tool_schema', 'invoke_tool']
    );

    const discRes = await core.handleCallTool('discover_tools', {
      query: 'search cloud',
      server: 'cloud',
      limit: 5
    });
    assert.ok(!discRes.isError);
    const discParsed = JSON.parse(discRes.content[0].text as string);
    assert.ok(discParsed.matches.length > 0);
    assert.equal(discParsed.matches[0].server, 'cloud');
    assert.ok(discParsed.matches[0].tool.includes('search_cloud_resource'));

    const targetTool = discParsed.matches[0].tool as string;
    const inspRes = await core.handleCallTool('inspect_tool_schema', {
      server: 'cloud',
      tool: targetTool
    });
    assert.ok(!inspRes.isError);
    const inspParsed = JSON.parse(inspRes.content[0].text as string);
    assert.equal(inspParsed.tool, targetTool);
    assert.ok(inspParsed.inputSchema.properties.targetId);

    const invRes = await core.handleCallTool('invoke_tool', {
      server: 'cloud',
      tool: targetTool,
      arguments: {
        targetId: 'res-42',
        token: 'sk-proj-1234567890abcdefghijklmnop',
        simulateOutputSecret: true
      }
    });
    assert.ok(!invRes.isError);
    const textOut = String(invRes.content[0].text);
    assert.ok(!textOut.includes('sk-proj-1234567890abcdefghijklmnop'));
    assert.ok(!textOut.includes('ghp_1234567890abcdefghij1234567890abcd'));
    assert.ok(textOut.includes('[REDACTED:API_KEY]'));
    assert.ok(textOut.includes('[REDACTED:GITHUB_TOKEN]'));

    const stats = ledger.getStats();
    assert.equal(stats.sessionsCount, 1);
    assert.equal(stats.totalEvents, 3);
    assert.equal(stats.allowedCalls, 3);
    assert.equal(stats.totalRedactions, 2);
  } finally {
    await upstream.closeAll();
    ledger.close();
  }
});

test('2. secret redactor masks AWS, GitHub, Stripe, OpenAI, Slack, JWT, and PEM secrets', () => {
  const sample = {
    aws: 'AKIAIOSFODNN7EXAMPLE',
    gh: 'github_pat_11AAAAAA00000000000000_abcdefghijklmnopqrstuvwxyz123456',
    stripe: ['sk', 'live', '51AbCdEfGhIjKlMnOpQrStUvWx'].join('_'),
    slack: ['xoxb', '123456789012', '123456789012', 'abcdefghijklmnop'].join('-'),
    jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    pem: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----'
  };
  const res = redactSecrets(sample);
  assert.equal(res.redactionCount, 6);
  assert.equal(res.sanitized.aws, '[REDACTED:AWS_KEY]');
  assert.equal(res.sanitized.gh, '[REDACTED:GITHUB_PAT]');
  assert.equal(res.sanitized.stripe, '[REDACTED:STRIPE_KEY]');
  assert.equal(res.sanitized.slack, '[REDACTED:SLACK_TOKEN]');
  assert.equal(res.sanitized.jwt, '[REDACTED:JWT]');
  assert.equal(res.sanitized.pem, '[REDACTED:PRIVATE_KEY]');
});

test('3. MIT PolicyGuard enforces RBAC deny rules, per-tool cap, and x402 spend cap with zero license gates', () => {
  const policy = {
    defaultAction: 'allow' as const,
    sessionLimits: {
      maxCallsPerSession: 5,
      maxX402AtomicUsdcPerSession: 20000
    },
    rules: [
      { pattern: '*:delete_*', action: 'deny' as const },
      {
        pattern: 'finance:pay_x402*',
        action: 'allow' as const,
        maxCallsPerSession: 3,
        estimatedX402AtomicUsdc: 10000
      }
    ]
  };

  const guard = new PolicyGuard(policy);
  assert.equal(guard.evaluate('cloud', 'delete_cloud_resource_6').code, 'DENIED_BY_POLICY');
  assert.equal(guard.evaluate('finance', 'pay_x402_finance_resource_10').allowed, true);
  assert.equal(guard.evaluate('finance', 'pay_x402_finance_resource_10').allowed, true);
  // 3rd call hits 30000 > 20000 atomic USDC cap
  const capRes = guard.evaluate('finance', 'pay_x402_finance_resource_10');
  assert.equal(capRes.allowed, false);
  assert.equal(capRes.code, 'X402_BUDGET_CAP');
});

test('4. Streamable-HTTP upstream MCP server connects cleanly and proxies discover/inspect/invoke', async () => {
  const mcpServer = new Server(
    { name: 'mock-http-mcp', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );
  mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'fetch_http_quote',
        description: 'Fetch a simulated remote quote over Streamable-HTTP MCP transport.',
        inputSchema: {
          type: 'object',
          properties: { ticker: { type: 'string' } },
          required: ['ticker']
        }
      }
    ]
  }));
  mcpServer.setRequestHandler(CallToolRequestSchema, async (req) => ({
    content: [{ type: 'text', text: `quote:${String((req.params.arguments as { ticker?: string })?.ticker || '')}` }]
  }));

  const serverTransport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID()
  });
  await mcpServer.connect(serverTransport);

  let seenAuthHeader = '';
  const httpServer = http.createServer(async (req, res) => {
    seenAuthHeader = String(req.headers['x-test-auth'] || '');
    let parsedBody: unknown;
    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
      const text = Buffer.concat(chunks).toString('utf8');
      parsedBody = text ? JSON.parse(text) : undefined;
    }
    await serverTransport.handleRequest(req, res, parsedBody);
  });

  await new Promise<void>((resolveListen) => httpServer.listen(0, '127.0.0.1', () => resolveListen()));
  const addr = httpServer.address() as AddressInfo;
  const endpointUrl = `http://127.0.0.1:${addr.port}/mcp`;

  const upstream = new UpstreamManager();
  const ledger = new MetricsLedger(':memory:');

  try {
    const serverTools = await upstream.connectAll([
      {
        id: 'remote-http',
        transport: 'streamable-http',
        url: endpointUrl,
        headers: { 'x-test-auth': 'slimmcp-ok' }
      }
    ]);
    assert.equal(serverTools.length, 1);
    assert.equal(serverTools[0].tools[0].name, 'fetch_http_quote');
    assert.equal(seenAuthHeader, 'slimmcp-ok');

    const indexer = new ToolIndexer();
    indexer.rebuild(serverTools);
    const sessionId = ledger.startSession(computeSchemaSavings(serverTools));
    const core = new SlimProxyCore({
      config: { servers: [] },
      upstream,
      indexer,
      policyGuard: new PolicyGuard(null),
      ledger,
      sessionId
    });

    const disc = await core.handleCallTool('discover_tools', { query: 'quote' });
    assert.ok(!disc.isError);
    assert.ok(String(disc.content[0].text).includes('fetch_http_quote'));

    const inv = await core.handleCallTool('invoke_tool', {
      server: 'remote-http',
      tool: 'fetch_http_quote',
      arguments: { ticker: 'ESZ26' }
    });
    assert.ok(!inv.isError);
    assert.equal(String(inv.content[0].text), 'quote:ESZ26');
  } finally {
    await upstream.closeAll();
    await serverTransport.close().catch(() => {});
    httpServer.close();
    ledger.close();
  }
});

test('5. CLI --help, status, and serve binary work end-to-end under MIT', async () => {
  const cliBin = resolve(process.cwd(), 'dist/src/cli.js');
  const configPath = resolve(process.cwd(), 'slimmcp.config.example.json');
  const tempHome = mkdtempSync(join(process.cwd(), '.tmp-e2e-'));

  const helpOut = execFileSync(process.execPath, [cliBin, '--help'], { encoding: 'utf8' });
  assert.ok(helpOut.includes('slimmcp-proxy serve'));

  const statusOut = JSON.parse(execFileSync(process.execPath, [cliBin, 'status', '--home', tempHome], { encoding: 'utf8' }));
  assert.equal(statusOut.mode, 'open-source-mit');
  assert.equal(statusOut.license, 'MIT');

  const transport = new StdioClientTransport({
    command: 'node',
    args: [cliBin, 'serve', '--config', configPath, '--home', tempHome],
    stderr: 'pipe'
  });
  const client = new Client({ name: 'qa-test-client', version: '1.0.2' }, { capabilities: {} });

  try {
    await client.connect(transport);
    const listRes = await client.listTools();
    assert.equal(listRes.tools.length, 3);

    const callRes = await client.callTool({
      name: 'discover_tools',
      arguments: { query: 'audit finance', limit: 3 }
    });
    const parsed = JSON.parse((callRes.content as Array<{ text: string }>)[0].text);
    assert.ok(parsed.totalIndexedTools === 60);
    assert.ok(parsed.matches.length >= 1);
  } finally {
    await client.close();
    rmSync(tempHome, { recursive: true, force: true });
  }
});
