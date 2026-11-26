import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  buildIsolatedChildEnv,
  computeSchemaSavings,
  globMatch,
  MetricsLedger,
  PolicyConfigSchema,
  PolicyGuard,
  redactSecrets,
  SlimProxyCore,
  ToolIndexer,
  UpstreamManager,
  validateUpstreamUrl
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
    assert.ok(stats.cumulativeTokensSaved > 0, 'Expected cumulativeTokensSaved > 0');
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
  const configPath = resolve(process.cwd(), 'slimmcp.benchmark.config.json');
  const tempHome = mkdtempSync(join(process.cwd(), '.tmp-e2e-'));

  assert.throws(
    () => execFileSync(process.execPath, [cliBin, 'serve', '--config', configPath, '--policy'], { encoding: 'utf8', stdio: 'pipe' }),
    /Command failed/
  );

  const helpOut = execFileSync(process.execPath, [cliBin, '--help'], { encoding: 'utf8' });
  assert.ok(helpOut.includes('slimmcp-proxy serve'));
  const shortHelpOut = execFileSync(process.execPath, [cliBin, '-h'], { encoding: 'utf8' });
  assert.ok(shortHelpOut.includes('slimmcp-proxy serve'));
  const shortVerOut = execFileSync(process.execPath, [cliBin, '-v'], { encoding: 'utf8' }).trim();
  assert.equal(shortVerOut, '1.0.2');
  const longVerOut = execFileSync(process.execPath, [cliBin, '--version'], { encoding: 'utf8' }).trim();
  assert.equal(longVerOut, '1.0.2');

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

test('6. secret redactor fails closed at depth > 24, redacts sensitive keys, and preserves normal prose', () => {
  // Depth > 24 must fail-closed with [REDACTED:MAX_DEPTH_EXCEEDED]
  let nested: Record<string, unknown> = { secret: 'never-leak-at-depth-26', note: 'deep-value' };
  for (let i = 0; i < 25; i++) {
    nested = { child: nested };
  }
  const depthRes = redactSecrets(nested);
  const serializedDepth = JSON.stringify(depthRes.sanitized);
  assert.ok(!serializedDepth.includes('never-leak-at-depth-26'));
  assert.ok(!serializedDepth.includes('deep-value'));
  assert.ok(serializedDepth.includes('[REDACTED:MAX_DEPTH_EXCEEDED]'));
  assert.ok(depthRes.matchedRules.includes('max_depth_exceeded'));

  // Key-based redaction + non-secret metric/boolean/prose preservation
  const payload = {
    secret: 'plain-opaque-secret',
    client_secret: 'opaque-client-secret',
    token: 'opaque-session-token',
    raw_token: 'opaque-raw-token',
    oauth_tokens: ['oauth-tok-1'],
    access_tokens: { primary: 'access-tok-1' },
    password: 'hunter2-password',
    apiKey: 'opaque-api-key-val',
    private_key: 'opaque-priv-key',
    mnemonic: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
    authorization: 'Bearer opaque-auth-header',
    cookie: 'session_id=abc123def456',
    credentials: { user: 'alice', pass: 's3cr3t' },
    otp_token: 482910,
    secret_saved: 'raw-secret-value',
    tokensSaved: 14725,
    maxTokens: 4096,
    rawSchemaTokens: 15047,
    simulateOutputSecret: true,
    prose: 'The user authorization flow uses token buckets and password rotation policies.'
  };
  const keyRes = redactSecrets(payload);
  assert.equal(keyRes.sanitized.secret, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.client_secret, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.token, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.raw_token, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.oauth_tokens, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.access_tokens, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.password, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.apiKey, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.private_key, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.mnemonic, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.authorization, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.cookie, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.credentials, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.otp_token, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.secret_saved, '[REDACTED:SENSITIVE_KEY]');
  assert.equal(keyRes.sanitized.tokensSaved, 14725);
  assert.equal(keyRes.sanitized.maxTokens, 4096);
  assert.equal(keyRes.sanitized.rawSchemaTokens, 15047);
  assert.equal(keyRes.sanitized.simulateOutputSecret, true);
  assert.equal(
    keyRes.sanitized.prose,
    'The user authorization flow uses token buckets and password rotation policies.'
  );

  // __proto__ prototype pollution guard
  const protoInput = JSON.parse('{"__proto__":{"polluted":true},"safe":"ok"}') as Record<string, unknown>;
  redactSecrets(protoInput);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);

  // Tightened secret/seed string patterns (including JSON ':' assignments, lowercase bearer, DB URIs)
  const stringSecrets = redactSecrets({
    gcp: 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt5x0',
    npm: 'npm_1234567890abcdefghijklmnop',
    hf: 'hf_1234567890abcdefghijklmnop',
    gl: 'glpat-1234567890abcdefghij',
    url: 'https://deploy:s3cr3tPass@registry.example.com/pkg',
    db: 'postgres://dbuser:s3cr3tPass@db.internal:5432/prod',
    bearerLower: 'bearer abcd1234efgh5678ijkl9012',
    jsonColon: '{"api_key": "supersecret123"}',
    seed: 'mnemonic="abandon ability able about above absent absorb abstract absurd abuse access accident"'
  });
  assert.equal(stringSecrets.sanitized.gcp, '[REDACTED:GCP_API_KEY]');
  assert.equal(stringSecrets.sanitized.npm, '[REDACTED:NPM_TOKEN]');
  assert.equal(stringSecrets.sanitized.hf, '[REDACTED:HF_TOKEN]');
  assert.equal(stringSecrets.sanitized.gl, '[REDACTED:GITLAB_PAT]');
  assert.equal(
    stringSecrets.sanitized.url,
    'https://deploy:[REDACTED:PASSWORD]@registry.example.com/pkg'
  );
  assert.equal(
    stringSecrets.sanitized.db,
    'postgres://dbuser:[REDACTED:PASSWORD]@db.internal:5432/prod'
  );
  assert.equal(stringSecrets.sanitized.bearerLower, 'Bearer [REDACTED:BEARER_TOKEN]');
  assert.equal(stringSecrets.sanitized.jsonColon, '{"api_key": "[REDACTED:SECRET]"}');
  assert.equal(stringSecrets.sanitized.seed, 'mnemonic="[REDACTED:MNEMONIC]"');
});

test('7. PolicyGuard prevents ReDoS, escapes ? metacharacter, and enforces strict deny-overrides', () => {
  // Unescaped ? metacharacter regression: '?' must match literal '?', never optional previous char
  assert.equal(globMatch('foo?bar', 'fobar'), false);
  assert.equal(globMatch('foo?bar', 'foobar'), false);
  assert.equal(globMatch('foo?bar', 'foo?bar'), true);

  // Adversarial ReDoS pattern must complete in linear/polynomial time (<100ms)
  const t0 = performance.now();
  const adversarial = 'a*'.repeat(25) + 'b';
  const nonMatchingTarget = 'a'.repeat(500) + 'c';
  assert.equal(globMatch(adversarial, nonMatchingTarget), false);
  assert.ok(performance.now() - t0 < 100, 'globMatch took too long on adversarial input');

  // Strict deny-overrides precedence: allow rule listed BEFORE deny rule must still deny
  const guard = new PolicyGuard({
    defaultAction: 'allow',
    rules: [
      { pattern: 'finance:*', action: 'allow' },
      { pattern: '*:delete_*', action: 'deny' }
    ]
  });
  const decision = guard.evaluate('finance', 'delete_ledger_entry');
  assert.equal(decision.allowed, false);
  assert.equal(decision.code, 'DENIED_BY_POLICY');

  const allowedDecision = guard.evaluate('finance', 'list_ledger_entries');
  assert.equal(allowedDecision.allowed, true);
  assert.equal(allowedDecision.code, 'ALLOWED');

  // Overlapping allow rules must enforce STRICTEST limits across all matching allow rules
  const overlapGuard = new PolicyGuard({
    defaultAction: 'deny',
    sessionLimits: {
      maxX402AtomicUsdcPerSession: 15000
    },
    rules: [
      { pattern: 'finance:*', action: 'allow' },
      {
        pattern: 'finance:pay_x402*',
        action: 'allow',
        maxCallsPerSession: 2,
        estimatedX402AtomicUsdc: 10000
      }
    ]
  });
  assert.equal(overlapGuard.evaluate('finance', 'pay_x402_1').allowed, true);
  const budgetBlocked = overlapGuard.evaluate('finance', 'pay_x402_1');
  assert.equal(budgetBlocked.allowed, false);
  assert.equal(budgetBlocked.code, 'X402_BUDGET_CAP');

  const toolCapGuard = new PolicyGuard({
    defaultAction: 'deny',
    rules: [
      { pattern: 'finance:*', action: 'allow', maxCallsPerSession: 10 },
      { pattern: 'finance:pay_x402*', action: 'allow', maxCallsPerSession: 1 }
    ]
  });
  assert.equal(toolCapGuard.evaluate('finance', 'pay_x402_1').allowed, true);
  const toolCapBlocked = toolCapGuard.evaluate('finance', 'pay_x402_1');
  assert.equal(toolCapBlocked.allowed, false);
  assert.equal(toolCapBlocked.code, 'TOOL_CALL_CAP');

  // Strict Zod schemas reject unknown keys fail-closed
  assert.throws(() =>
    PolicyConfigSchema.parse({ defaultAction: 'allow', unknownTypoKey: true })
  );
  assert.throws(() =>
    PolicyConfigSchema.parse({
      defaultAction: 'allow',
      rules: [{ pattern: 'finance:*', action: 'allow', unknownRuleField: 1 }]
    })
  );

  // Rules containing ':' match full server:tool key ONLY (untrusted server cannot spoof toolName)
  const scopedGuard = new PolicyGuard({
    defaultAction: 'deny',
    rules: [{ pattern: 'finance:*', action: 'allow' }]
  });
  assert.equal(scopedGuard.evaluate('evil', 'finance:export').allowed, false);
  assert.equal(scopedGuard.evaluate('evil', 'finance:export').code, 'DENIED_BY_POLICY');
  assert.equal(scopedGuard.evaluate('finance', 'export').allowed, true);
});

test('8. UpstreamManager isolates child env from host CI secrets and enforces timeouts', async () => {
  const prevGh = process.env.GITHUB_TOKEN;
  const prevNpm = process.env.NPM_TOKEN;
  const prevCustom = process.env.SLIMMCP_TEST_ALLOWED;
  process.env.GITHUB_TOKEN = 'ghp_host_ci_secret_must_not_leak';
  process.env.NPM_TOKEN = 'npm_host_ci_secret_must_not_leak';
  process.env.SLIMMCP_TEST_ALLOWED = 'opt-in-ok';

  try {
    const isolated = buildIsolatedChildEnv(
      { EXPLICIT_CHILD_VAR: 'explicit-ok' },
      ['SLIMMCP_TEST_ALLOWED']
    );
    assert.equal('GITHUB_TOKEN' in isolated, false);
    assert.equal('NPM_TOKEN' in isolated, false);
    assert.equal(isolated.SLIMMCP_TEST_ALLOWED, 'opt-in-ok');
    assert.equal(isolated.EXPLICIT_CHILD_VAR, 'explicit-ok');

    // Verify real stdio child does NOT inherit GITHUB_TOKEN or NPM_TOKEN even when cfg.env is provided
    const sdkEntry = resolve(process.cwd(), 'node_modules/@modelcontextprotocol/sdk/dist/esm');
    const sdkServerUrl = pathToFileURL(join(sdkEntry, 'server/index.js')).href;
    const sdkStdioUrl = pathToFileURL(join(sdkEntry, 'server/stdio.js')).href;
    const sdkTypesUrl = pathToFileURL(join(sdkEntry, 'types.js')).href;
    const envProbeScript = `
      import { Server } from ${JSON.stringify(sdkServerUrl)};
      import { StdioServerTransport } from ${JSON.stringify(sdkStdioUrl)};
      import { CallToolRequestSchema, ListToolsRequestSchema } from ${JSON.stringify(sdkTypesUrl)};
      const server = new Server({ name: 'env-probe', version: '1.0.0' }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [{ name: 'probe_env', description: 'Probe env', inputSchema: { type: 'object', properties: {} } }]
      }));
      server.setRequestHandler(CallToolRequestSchema, async () => ({
        content: [{
          type: 'text',
          text: JSON.stringify({
            hasGithubToken: Boolean(process.env.GITHUB_TOKEN),
            hasNpmToken: Boolean(process.env.NPM_TOKEN),
            explicit: process.env.EXPLICIT_CHILD_VAR ?? null
          })
        }]
      }));
      await server.connect(new StdioServerTransport());
    `;
    const probeUpstream = new UpstreamManager({ connectTimeoutMs: 15000, requestTimeoutMs: 15000 });
    try {
      await probeUpstream.connectAll([
        {
          id: 'env-probe',
          command: process.execPath,
          args: ['--input-type=module', '-e', envProbeScript],
          env: { EXPLICIT_CHILD_VAR: 'explicit-ok' }
        }
      ]);
      const probeRes = await probeUpstream.callTool('env-probe', 'probe_env', {});
      const parsed = JSON.parse(String(probeRes.content[0].text));
      assert.equal(parsed.hasGithubToken, false);
      assert.equal(parsed.hasNpmToken, false);
      assert.equal(parsed.explicit, 'explicit-ok');
    } finally {
      await probeUpstream.closeAll();
    }

    // Verify hung connect fails cleanly on timeout
    const hungConnectUpstream = new UpstreamManager({ connectTimeoutMs: 250, requestTimeoutMs: 250 });
    await assert.rejects(
      hungConnectUpstream.connectAll([
        {
          id: 'hung-connect',
          command: process.execPath,
          args: ['-e', 'setTimeout(() => {}, 10000)']
        }
      ]),
      /timed out/i
    );
    await hungConnectUpstream.closeAll();

    // Verify hung tool call fails cleanly on requestTimeoutMs
    const hungCallScript = `
      import { Server } from ${JSON.stringify(sdkServerUrl)};
      import { StdioServerTransport } from ${JSON.stringify(sdkStdioUrl)};
      import { CallToolRequestSchema, ListToolsRequestSchema } from ${JSON.stringify(sdkTypesUrl)};
      const server = new Server({ name: 'hung-call', version: '1.0.0' }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [{ name: 'hang_forever', description: 'Hang', inputSchema: { type: 'object', properties: {} } }]
      }));
      server.setRequestHandler(CallToolRequestSchema, async () => new Promise(() => {}));
      await server.connect(new StdioServerTransport());
    `;
    const hungCallUpstream = new UpstreamManager({ connectTimeoutMs: 15000, requestTimeoutMs: 250 });
    try {
      await hungCallUpstream.connectAll([
        {
          id: 'hung-call',
          command: process.execPath,
          args: ['--input-type=module', '-e', hungCallScript]
        }
      ]);
      await assert.rejects(
        hungCallUpstream.callTool('hung-call', 'hang_forever', {}),
        /timed out/i
      );
    } finally {
      await hungCallUpstream.closeAll();
    }

    // Verify URL scheme & cloud metadata IP SSRF restrictions (including IPv4-mapped IPv6 & redirects)
    assert.throws(() => validateUpstreamUrl('file:///etc/passwd'), /Unsupported upstream URL scheme/);
    assert.throws(() => validateUpstreamUrl('http://169.254.169.254/latest/meta-data/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://metadata.google.internal./computeMetadata/v1/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[::ffff:169.254.169.254]/latest/meta-data/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[0:0:0:0:0:ffff:a9fe:a9fe]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[::ffff:100.100.100.200]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[fe80::1]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[febf::1]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[fd00:0ec2::0254]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[::]/'), /Blocked cloud metadata/);
    assert.throws(() => validateUpstreamUrl('http://[64:ff9b::169.254.169.254]/'), /Blocked cloud metadata/);
    assert.equal(validateUpstreamUrl('http://127.0.0.1:8080/mcp').hostname, '127.0.0.1');
    assert.equal(validateUpstreamUrl('http://localhost:8080/mcp').hostname, 'localhost');
    assert.equal(validateUpstreamUrl('http://[::ffff:127.0.0.1]:8080/mcp').protocol, 'http:');

    // Verify HTTP redirect to metadata is blocked via redirect: 'error'
    const redirectServer = http.createServer((_req, res) => {
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });
    await new Promise<void>((resolveListen) => redirectServer.listen(0, '127.0.0.1', () => resolveListen()));
    const redirectAddr = redirectServer.address() as AddressInfo;
    const redirectUpstream = new UpstreamManager({ connectTimeoutMs: 5000, requestTimeoutMs: 5000 });
    try {
      await assert.rejects(
        redirectUpstream.connectAll([
          {
            id: 'redirect-ssrf',
            transport: 'streamable-http',
            url: `http://127.0.0.1:${redirectAddr.port}/mcp`
          }
        ])
      );
    } finally {
      await redirectUpstream.closeAll();
      redirectServer.close();
    }

    // Verify noisy stderr (>128KB) does not deadlock piped stdio upstream
    const noisyScript = `
      import { Server } from ${JSON.stringify(sdkServerUrl)};
      import { StdioServerTransport } from ${JSON.stringify(sdkStdioUrl)};
      import { CallToolRequestSchema, ListToolsRequestSchema } from ${JSON.stringify(sdkTypesUrl)};
      process.stderr.write('X'.repeat(150 * 1024) + '\\n');
      const server = new Server({ name: 'noisy-stderr', version: '1.0.0' }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [{ name: 'ping_noisy', description: 'Ping', inputSchema: { type: 'object', properties: {} } }]
      }));
      server.setRequestHandler(CallToolRequestSchema, async () => ({
        content: [{ type: 'text', text: 'pong' }]
      }));
      await server.connect(new StdioServerTransport());
    `;
    const noisyUpstream = new UpstreamManager({ connectTimeoutMs: 15000, requestTimeoutMs: 5000 });
    try {
      await noisyUpstream.connectAll([
        {
          id: 'noisy',
          command: process.execPath,
          args: ['--input-type=module', '-e', noisyScript]
        }
      ]);
      const pong = await noisyUpstream.callTool('noisy', 'ping_noisy', {});
      assert.equal(String(pong.content[0].text), 'pong');
    } finally {
      await noisyUpstream.closeAll();
    }

    // Verify SlimProxyCore redacts secrets inside thrown upstream error messages
    const errLedger = new MetricsLedger(':memory:');
    try {
      const errIndexer = new ToolIndexer();
      errIndexer.rebuild([
        {
          serverId: 'mock',
          tools: [{ name: 'fail_with_secret', description: 'Fails', inputSchema: { type: 'object', properties: {} } }]
        }
      ]);
      const fakeUpstream = {
        callTool: async () => {
          throw new Error('Connection failed to postgres://admin:superSecret99@db.internal:5432/prod');
        }
      } as unknown as UpstreamManager;
      const errCore = new SlimProxyCore({
        config: { servers: [] },
        upstream: fakeUpstream,
        indexer: errIndexer,
        policyGuard: new PolicyGuard(null),
        ledger: errLedger,
        sessionId: errLedger.startSession({
          rawToolsCount: 1,
          rawSchemaBytes: 100,
          rawSchemaTokens: 25,
          slimExposedBytes: 100,
          slimExposedTokens: 25
        })
      });
      const errRes = await errCore.handleCallTool('invoke_tool', {
        server: 'mock',
        tool: 'fail_with_secret',
        arguments: {}
      });
      assert.equal(errRes.isError, true);
      const errText = String(errRes.content[0].text);
      assert.ok(!errText.includes('superSecret99'));
      assert.ok(errText.includes('[REDACTED:PASSWORD]'));

      // Verify discover_tools & inspect_tool_schema redact embedded secrets while preserving schema properties
      const discSecretIndexer = new ToolIndexer();
      discSecretIndexer.rebuild([
        {
          serverId: 'mock',
          tools: [
            {
              name: 'login_tool',
              description: 'Auth helper using key sk-proj-1234567890abcdefghijklmnop',
              inputSchema: {
                type: 'object',
                properties: {
                  password: { type: 'string', description: 'User password' }
                }
              }
            }
          ]
        }
      ]);
      const discSecretCore = new SlimProxyCore({
        config: { servers: [] },
        upstream: fakeUpstream,
        indexer: discSecretIndexer,
        policyGuard: new PolicyGuard(null),
        ledger: errLedger,
        sessionId: errLedger.startSession({
          rawToolsCount: 1,
          rawSchemaBytes: 100,
          rawSchemaTokens: 25,
          slimExposedBytes: 100,
          slimExposedTokens: 25
        })
      });
      const discSecretRes = await discSecretCore.handleCallTool('discover_tools', { query: 'login' });
      const discSecretText = String(discSecretRes.content[0].text);
      assert.ok(!discSecretText.includes('sk-proj-1234567890abcdefghijklmnop'));
      assert.ok(discSecretText.includes('[REDACTED:API_KEY]'));

      const inspSecretRes = await discSecretCore.handleCallTool('inspect_tool_schema', {
        server: 'mock',
        tool: 'login_tool'
      });
      const inspSecretParsed = JSON.parse(String(inspSecretRes.content[0].text));
      assert.ok(!String(inspSecretParsed.description).includes('sk-proj-1234567890abcdefghijklmnop'));
      assert.ok(String(inspSecretParsed.description).includes('[REDACTED:API_KEY]'));
      assert.equal(inspSecretParsed.inputSchema.properties.password.type, 'string');
    } finally {
      errLedger.close();
    }
  } finally {
    if (prevGh === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = prevGh;
    if (prevNpm === undefined) delete process.env.NPM_TOKEN;
    else process.env.NPM_TOKEN = prevNpm;
    if (prevCustom === undefined) delete process.env.SLIMMCP_TEST_ALLOWED;
    else process.env.SLIMMCP_TEST_ALLOWED = prevCustom;
  }
});
