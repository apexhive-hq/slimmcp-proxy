import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import appSlim from '../src/index.ts';

const PAY_TO = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function makeLog(token, from, to, atomic) {
  return {
    address: token,
    topics: [TRANSFER_TOPIC, pad(from, { size: 32 }), pad(to, { size: 32 })],
    data: encodeAbiParameters([{ type: 'uint256' }], [atomic])
  };
}

function createMemoryKv() {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, val) {
      store.set(key, val);
    },
    async delete(key) {
      store.delete(key);
    }
  };
}

function baseSlimEnv(kv, globalKv, overrides = {}) {
  return {
    LICENSES_KV: kv,
    GLOBAL_CLAIMED_TX_KV: globalKv,
    BRAND_NAME: 'ApexHive Labs',
    PRODUCT_ID: 'slimmcp-proxy',
    PAY_TO_EVM_ADDRESS: PAY_TO,
    BASE_USDC_CONTRACT: BASE_USDC,
    BASE_CHAIN_ID: '8453',
    BASE_RPC_URL: 'http://127.0.0.1:4199',
    PRO_PRICE_USDC_ATOMIC: '5000000',
    TEAM_PRICE_USDC_ATOMIC: '49000000',
    MIN_CONFIRMATIONS: '2',
    SOLANA_RECEIVE_ADDRESS: 'sol',
    BTC_RECEIVE_ADDRESS: 'btc',
    TRON_RECEIVE_ADDRESS: 'tron',
    ...overrides
  };
}

test('/api/verify fails closed 500 BEFORE consuming challenge nonce when LICENSE_SIGNING_PRIVATE_JWK missing', async () => {
  const kv = createMemoryKv();
  const globalKv = createMemoryKv();
  const env = baseSlimEnv(kv, globalKv);
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'aa'.repeat(32);

  const chRes = await appSlim.request(
    '/api/challenge',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, tier: 'indie' })
    },
    env
  );
  assert.equal(chRes.status, 200);
  const ch = await chRes.json();
  const sig = await payer.signMessage({ message: ch.message });

  const res = await appSlim.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'indie' })
    },
    env
  );
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, 'SERVER_MISCONFIGURED');
  assert.ok(await kv.get(`challenge:${ch.nonce}`), 'Challenge nonce must NOT be deleted on 500');
});

test('Playground rejects oversized payload (413) & deep nesting (400), and exposes CORS + UTF-8 headers', async () => {
  const kv = createMemoryKv();
  const globalKv = createMemoryKv();
  const env = baseSlimEnv(kv, globalKv);

  const huge = 'x'.repeat(270_000);
  const resHuge = await appSlim.request(
    '/api/playground/compress',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tools: [{ name: 't', description: huge }] })
    },
    env
  );
  assert.equal(resHuge.status, 413);
  assert.equal(resHuge.headers.get('access-control-allow-origin'), '*');
  assert.ok(resHuge.headers.get('content-type')?.includes('charset=utf-8'));

  const deep = '['.repeat(40) + '1' + ']'.repeat(40);
  const resDeep = await appSlim.request(
    '/api/playground/compress',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: deep
    },
    env
  );
  assert.equal(resDeep.status, 400);
  assert.equal((await resDeep.json()).error, 'NESTING_DEPTH_EXCEEDED');
});

test('Shared GLOBAL_CLAIMED_TX_KV blocks cross-product (#2 -> #1) and cross-endpoint (#1 storefront -> x402) replay', async () => {
  const kv1 = createMemoryKv();
  const globalKv = createMemoryKv();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'f1'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 5_000_000n)]
      }
    });
  };

  try {
    const env1 = baseSlimEnv(kv1, globalKv, {
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64
    });

    // 1. Claim txHash on #1 storefront (storefront:slimmcp) -> 200
    const ch1 = await (
      await appSlim.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash, tier: 'indie' })
        },
        env1
      )
    ).json();
    const sig1 = await payer.signMessage({ message: ch1.message });
    const v1 = await appSlim.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch1.nonce, signature: sig1, tier: 'indie' })
      },
      env1
    );
    assert.equal(v1.status, 200);

    // 2. Attempt to reuse same txHash on #1 POST /api/x402/compress -> 403 TX_ALREADY_CLAIMED_ELSEWHERE
    const x402Sig = await payer.signMessage({
      message: `ApexHive x402 slimmcp-compress\ntxHash:${txHash}`
    });
    const resX402 = await appSlim.request(
      '/api/x402/compress',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'X-Payment': txHash,
          'X-Payment-Signature': x402Sig,
          'X-Payment-Address': payer.address
        },
        body: JSON.stringify({ tools: [{ name: 't1', description: 'demo' }] })
      },
      env1
    );
    assert.equal(resX402.status, 403);
    assert.equal((await resX402.json()).error, 'TX_ALREADY_CLAIMED_ELSEWHERE');

    // 3. Pre-seeded foreign scope ("storefront:zerofiat") in shared GLOBAL_CLAIMED_TX_KV -> 403 TX_ALREADY_CLAIMED_ELSEWHERE on #1
    const foreignTx = '0x' + 'f3'.repeat(32);
    await globalKv.put(
      `global_tx:${foreignTx}`,
      JSON.stringify({
        scope: 'storefront:zerofiat',
        payer: payer.address,
        tier: 'supporter',
        txHash: foreignTx,
        claimedAt: Date.now()
      })
    );
    const chForeign = await (
      await appSlim.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: foreignTx, tier: 'indie' })
        },
        env1
      )
    ).json();
    const sigForeign = await payer.signMessage({ message: chForeign.message });
    const vForeign = await appSlim.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: foreignTx, nonce: chForeign.nonce, signature: sigForeign, tier: 'indie' })
      },
      env1
    );
    assert.equal(vForeign.status, 403);
    assert.equal((await vForeign.json()).error, 'TX_ALREADY_CLAIMED_ELSEWHERE');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Strict hex validation rejects malformed RPC blockNumber ("0x") with 403 fail-closed', async () => {
  const kv = createMemoryKv();
  const globalKv = createMemoryKv();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const env = baseSlimEnv(kv, globalKv, {
    LICENSE_SIGNING_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: 'jwk' })),
    LICENSE_SIGNING_PUBLIC_SPKI_B64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  });
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'f2'.repeat(32);

  const ch = await (
    await appSlim.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier: 'indie' })
      },
      env
    )
  ).json();
  const sig = await payer.signMessage({ message: ch.message });

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x' });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 5_000_000n)]
      }
    });
  };

  try {
    const res = await appSlim.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'indie' })
      },
      env
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, 'TX_NOT_CONFIRMED');
  } finally {
    globalThis.fetch = origFetch;
  }
});
