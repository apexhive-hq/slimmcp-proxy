import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  computeSchemaSavings,
  loadActivatedLicense,
  MetricsLedger,
  PolicyGuard,
  redactSecrets,
  saveActivatedLicense,
  SlimProxyCore,
  ToolIndexer,
  UpstreamManager,
  verifyProLicenseToken
} from '../src/index.js';

function createEphemeralTestLicense(tier: 'indie' | 'team' = 'indie', expiresAt: number | null = null) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeySpkiB64 = (
    publicKey.export({ type: 'spki', format: 'der' }) as Buffer
  ).toString('base64');

  const payload = {
    v: 1 as const,
    product: 'slimmcp-proxy' as const,
    tier,
    payer: '0x1111111111111111111111111111111111111111',
    txHash: '0x' + 'ab'.repeat(32),
    issuedAt: Date.now(),
    expiresAt
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const prefix = 'APEXHIVE-PRO-v1.';
  const sig = sign(null, Buffer.from(`${prefix}${payloadB64}`, 'utf8'), privateKey).toString(
    'base64url'
  );
  return { token: `${prefix}${payloadB64}.${sig}`, publicKeySpkiB64, payload };
}

test('real stdio MCP proxy achieves >=85% context reduction and full progressive tool execution', async () => {
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
      policyGuard: new PolicyGuard(null, false),
      ledger,
      sessionId
    });

    // 1. List tools exposes only 3 meta-tools
    const listRes = await core.handleListTools();
    assert.deepEqual(
      listRes.tools.map((t) => t.name),
      ['discover_tools', 'inspect_tool_schema', 'invoke_tool']
    );

    // 2. Discover tools via BM25
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

    // 3. Inspect single tool schema
    const targetTool = discParsed.matches[0].tool as string;
    const inspRes = await core.handleCallTool('inspect_tool_schema', {
      server: 'cloud',
      tool: targetTool
    });
    assert.ok(!inspRes.isError);
    const inspParsed = JSON.parse(inspRes.content[0].text as string);
    assert.equal(inspParsed.tool, targetTool);
    assert.ok(inspParsed.inputSchema.properties.targetId);

    // 4. Invoke upstream tool with secret in input & simulated secret in output -> both redacted
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

test('secret redactor masks AWS, GitHub, Stripe, OpenAI, Slack, JWT, and PEM secrets', () => {
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

test('Ed25519 Pro license verification handles valid, tampered, expired, and disk persistence', () => {
  const { token, publicKeySpkiB64 } = createEphemeralTestLicense('indie');
  const ok = verifyProLicenseToken(token, { publicKeySpkiB64 });
  assert.equal(ok.valid, true);
  assert.equal(ok.payload?.tier, 'indie');

  // Tamper payload
  const parts = token.split('.');
  const fakePayload = Buffer.from(JSON.stringify({ v: 1, product: 'slimmcp-proxy', tier: 'team' })).toString('base64url');
  const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;
  assert.equal(verifyProLicenseToken(tampered, { publicKeySpkiB64 }).valid, false);

  // Wrong key
  const other = createEphemeralTestLicense('team');
  assert.equal(
    verifyProLicenseToken(token, { publicKeySpkiB64: other.publicKeySpkiB64 }).valid,
    false
  );

  // Expired token
  const expired = createEphemeralTestLicense('indie', Date.now() - 1000);
  assert.equal(
    verifyProLicenseToken(expired.token, { publicKeySpkiB64: expired.publicKeySpkiB64 }).valid,
    false
  );

  // Save & load in isolated HQ sandbox dir
  const tempHome = mkdtempSync(join(process.cwd(), '.tmp-home-'));
  try {
    saveActivatedLicense(token, { homeDir: tempHome, publicKeySpkiB64 });
    const loaded = loadActivatedLicense({ homeDir: tempHome, publicKeySpkiB64 });
    assert.equal(loaded.valid, true);
    assert.equal(loaded.payload?.tier, 'indie');
  } finally {
    rmSync(tempHome, { recursive: true, force: true });
  }
});

test('Pro PolicyGuard enforces license gate, RBAC deny rules, per-tool cap, and x402 spend cap', () => {
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

  // Unlicensed blocks policy usage
  const freeGuard = new PolicyGuard(policy, false);
  const freeRes = freeGuard.evaluate('cloud', 'list_cloud_resource_1');
  assert.equal(freeRes.allowed, false);
  assert.equal(freeRes.code, 'PRO_LICENSE_REQUIRED');

  // Licensed enforces RBAC + caps
  const proGuard = new PolicyGuard(policy, true);
  assert.equal(proGuard.evaluate('cloud', 'delete_cloud_resource_6').code, 'DENIED_BY_POLICY');
  assert.equal(proGuard.evaluate('finance', 'pay_x402_finance_resource_10').allowed, true);
  assert.equal(proGuard.evaluate('finance', 'pay_x402_finance_resource_10').allowed, true);
  // 3rd call hits 30000 > 20000 atomic USDC cap
  const capRes = proGuard.evaluate('finance', 'pay_x402_finance_resource_10');
  assert.equal(capRes.allowed, false);
  assert.equal(capRes.code, 'X402_BUDGET_CAP');
});

test('CLI serve binary works over full MCP stdio transport end-to-end', async () => {
  const cliBin = resolve(process.cwd(), 'dist/src/cli.js');
  const configPath = resolve(process.cwd(), 'slimmcp.config.example.json');
  const tempHome = mkdtempSync(join(process.cwd(), '.tmp-e2e-'));

  const transport = new StdioClientTransport({
    command: 'node',
    args: [cliBin, 'serve', '--config', configPath, '--home', tempHome],
    stderr: 'pipe'
  });
  const client = new Client({ name: 'qa-test-client', version: '1.0.0' }, { capabilities: {} });

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
