import assert from 'node:assert/strict';
import test from 'node:test';
import { fixture } from './support/mcp-fixture.js';
import { OAuthConnection } from '../src/oauth.js';
import { credentialId, endpoint, loopback, restrictedFetch } from '../src/security.js';

export function memoryCredentials() {
  const records = new Map();
  let tail = Promise.resolve();
  return {
    records,
    readRecord: async key => structuredClone(records.get(key)),
    modifyRecord(key, change) {
      assert.ok(key.split('/').length === 2 && key.split('/').every(part => /^[a-z][a-z0-9-]*$/.test(part)), 'DSH credential key grammar');
      const next = tail.then(async () => {
        const value = await change(structuredClone(records.get(key)));
        if (value !== undefined) {
          const json = JSON.parse(JSON.stringify(value));
          assert.deepEqual(value, json, 'DSH credential records must be JSON round-trippable');
          records.set(key, json);
        }
      });
      tail = next.catch(() => {}); return next;
    },
    async deleteRecord(key) { await tail; records.delete(key); },
  };
}


test('real MCP SDK: browser callback + PKCE, rotating refresh, restart, logout, isolated bindings', async () => {
  const f = await fixture();
  const credentials = memoryCredentials();
  const config = { serverName: 'test', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true };
  let connection = new OAuthConnection(config, credentials);
  try {
    const login = await connection.startLogin();
    assert.equal(connection.status, 'authorizing');
    const auth = await fetch(login.authorizationUrl, { redirect: 'manual' });
    const callback = auth.headers.get('location');
    assert.equal((await fetch(callback)).status, 200);
    await login.finished;
    assert.equal(connection.status, 'connected');
    assert.equal(f.writes, 0, 'sign-in must never call a business tool');
    const tool = (await connection.client.listTools()).tools[0];
    assert.equal((await connection.call(tool, { text: 'hello' })).content[0].text, 'hello');
    await credentials.modifyRecord(connection.key, async current => ({ ...current, payload: { ...current.payload, expiresAt: 0 } }));
    await connection.call(tool, { text: 'after refresh' });
    assert.equal(f.refreshes, 1);
    await connection.dispose();
    connection = new OAuthConnection(config, credentials);
    await connection.connect();
    assert.equal(connection.status, 'connected');
    const other = new OAuthConnection({ ...config, url: f.base + '/other' }, credentials);
    await assert.rejects(other.connect(), /sign-in required/i);
    await other.dispose();
    await connection.logout();
    assert.equal(await credentials.readRecord(connection.key), undefined);
    await assert.rejects(connection.connect(), /sign-in required/i);
  } finally { await connection.dispose(); await f.close(); }
});

test('loopback rejects foreign Host/Origin, bad or duplicate state; callback consumed once', async () => {
  const listener = await loopback({ timeoutMs: 2000 });
  const good = new URL(listener.redirectUrl);
  good.searchParams.set('state', listener.state); good.searchParams.set('code', 'code');
  try {
    assert.equal((await fetch(good, { headers: { origin: 'https://foreign.invalid' } })).status, 400);
    const bad = new URL(good); bad.searchParams.set('state', 'é'.repeat(43));
    assert.equal((await fetch(bad)).status, 400);
    const duplicate = new URL(good); duplicate.searchParams.append('state', listener.state);
    assert.equal((await fetch(duplicate)).status, 400);
    assert.equal((await fetch(good)).status, 200);
    assert.equal((await listener.result).code, 'code');
    await assert.rejects(fetch(good));
  } finally { listener.cancel(); }
});

test('wrong callback issuer cannot exchange code or persist tokens', async () => {
  const f = await fixture();
  const credentials = memoryCredentials();
  const connection = new OAuthConnection({ serverName: 'issuer', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true }, credentials);
  try {
    const login = await connection.startLogin();
    const response = await fetch(login.authorizationUrl, { redirect: 'manual' });
    const callback = new URL(response.headers.get('location'));
    callback.searchParams.set('iss', 'https://attacker.invalid');
    await fetch(callback);
    await assert.rejects(login.finished, /issuer|authorization server/i);
    assert.equal((await credentials.readRecord(connection.key)).payload.tokens, undefined);
    assert.equal(f.writes, 0);
  } finally { await connection.dispose(); await f.close(); }
});

test('concurrent hosts serialize rotating refresh tokens through the credential backend', async () => {
  const f = await fixture();
  const credentials = memoryCredentials();
  const config = { serverName: 'shared', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true };
  const first = new OAuthConnection(config, credentials);
  const second = new OAuthConnection(config, credentials);
  try {
    const login = await first.startLogin();
    const response = await fetch(login.authorizationUrl, { redirect: 'manual' });
    await fetch(response.headers.get('location')); await login.finished;
    await second.connect();
    const tool = (await first.client.listTools()).tools[0];
    await credentials.modifyRecord(first.key, async current => ({ ...current, payload: { ...current.payload, expiresAt: 0 } }));
    await Promise.all([first.call(tool, { text: 'one' }), second.call(tool, { text: 'two' })]);
    assert.equal(f.refreshes, 1);
    assert.equal((await credentials.readRecord(first.key)).payload.tokens.refresh_token, 'refresh-1');
  } finally { await first.dispose(); await second.dispose(); await f.close(); }
});

test('logout cancels a pending browser flow and cannot recreate its credentials', async () => {
  const f = await fixture();
  const credentials = memoryCredentials();
  const connection = new OAuthConnection({ serverName: 'cancel', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true }, credentials);
  try {
    const login = await connection.startLogin();
    await connection.logout();
    await assert.rejects(login.finished, /cancelled/);
    assert.equal(connection.status, 'signed_out');
    assert.equal(await credentials.readRecord(connection.key), undefined);
    assert.equal(f.writes, 0);
  } finally { await connection.dispose(); await f.close(); }
});

test('bounded sign-in cancellation and credential partitioning', async () => {
  const callback = await loopback({ timeoutMs: 10 });
  await assert.rejects(callback.result, /timed out/);
  const config = { serverName: 'x', url: 'https://mcp.invalid/mcp', authorizationOrigins: [] };
  assert.notEqual(credentialId(config), credentialId({ ...config, scope: 'write' }));
  assert.notEqual(credentialId(config), credentialId({ ...config, authorizationOrigins: ['https://auth.invalid'] }));
  for (let i = 0; i < 32; i++) assert.ok(credentialId({ ...config, scope: String(i) }).split('/').every(part => /^[a-z][a-z0-9-]*$/.test(part)));
});

test('parallel sign-in initialization creates one attempt only', async () => {
  const f = await fixture();
  const connection = new OAuthConnection({ serverName: 'single', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true }, memoryCredentials());
  try {
    const results = await Promise.allSettled([connection.startLogin(), connection.startLogin()]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.match(results.find(result => result.status === 'rejected').reason.message, /already starting/);
    await connection.logout();
  } finally { await connection.dispose(); await f.close(); }
});

test('logout while initialization is opening cannot create a late sign-in', async () => {
  const f = await fixture();
  const credentials = memoryCredentials();
  const connection = new OAuthConnection({ serverName: 'opening', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true }, credentials);
  try {
    const starting = connection.startLogin();
    const rejected = assert.rejects(starting, /cancelled/);
    await connection.logout();
    await rejected;
    assert.equal(connection.pending, undefined);
    assert.equal(await credentials.readRecord(connection.key), undefined);
  } finally { await connection.dispose(); await f.close(); }
});

test('cancellation during code exchange cannot persist a late credential', async () => {
  let entered, release;
  const tokenEntered = new Promise(resolve => { entered = resolve; });
  const hold = new Promise(resolve => { release = resolve; });
  const f = await fixture({ beforeTokenResponse: async () => { entered(); await hold; } });
  const credentials = memoryCredentials();
  const connection = new OAuthConnection({ serverName: 'late', url: f.base + '/mcp', scope: 'mcp', allowInsecureLoopback: true }, credentials);
  try {
    const login = await connection.startLogin();
    const response = await fetch(login.authorizationUrl, { redirect: 'manual' });
    await fetch(response.headers.get('location'));
    await tokenEntered;
    await connection.logout();
    release();
    await assert.rejects(login.finished, /abort|cancel/i);
    assert.equal(await credentials.readRecord(connection.key), undefined);
    assert.equal(connection.status, 'signed_out');
    assert.equal(f.writes, 0);
  } finally { release(); await connection.dispose(); await f.close(); }
});

test('rejects HTTP, credential URLs, untrusted discovery and redirected credential requests', async () => {
  for (const url of ['http://service.invalid/mcp', 'https://u:p@service.invalid/mcp', 'https://service.invalid/mcp?token=secret']) assert.throws(() => endpoint(url));
  let called = false;
  const safe = restrictedFetch({ url: 'https://service.invalid/mcp', authorizationOrigins: [] }, async () => { called = true; });
  await assert.rejects(safe('https://attacker.invalid/token', { body: 'secret' }), /untrusted origin/);
  assert.equal(called, false);
  const check = restrictedFetch({ url: 'https://service.invalid/mcp', authorizationOrigins: [] }, async (_url, options) => {
    assert.equal(options.redirect, 'error'); return new Response('{}', { headers: { 'content-type': 'application/json' } });
  });
  assert.deepEqual(await (await check('https://service.invalid/token')).json(), {});
});

test('caps chunked JSON responses before parsing', async () => {
  const safe = restrictedFetch({ url: 'https://service.invalid/mcp', authorizationOrigins: [] }, async () =>
    new Response('x'.repeat(4 * 1024 * 1024 + 1), { headers: { 'content-type': 'application/json' } }));
  await assert.rejects((await safe('https://service.invalid/metadata')).text(), /exceeded/);
});
