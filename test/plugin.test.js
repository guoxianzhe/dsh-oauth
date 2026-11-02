import assert from 'node:assert/strict';
import test from 'node:test';
import { apply, Config, toolName } from '../src/index.js';
import { fixture } from './support/mcp-fixture.js';

test('DSH adapter loads with no network, saves configuration, authorizes and registers tools', async () => {
  const service = await fixture();
  const records = new Map(), tools = new Map(), flows = new Map(), handlers = new Map(), cleanups = [];
  const credentials = {
    readRecord: async key => records.get(key),
    modifyRecord: async (key, change) => {
      const value = await change(records.get(key));
      if (value) { const json = JSON.parse(JSON.stringify(value)); assert.deepEqual(value, json); records.set(key, json); }
    },
    deleteRecord: async key => { records.delete(key); },
  };
  const ctx = {
    credentials,
    tools: { register(definition) { assert.ok(!tools.has(definition.name)); tools.set(definition.name, definition); return () => tools.delete(definition.name); } },
    authorization: { registerFlow(flow) { flows.set(flow.key, flow); return () => flows.delete(flow.key); } },
    effect(factory) { cleanups.push(factory()); },
    inject(_services, callback) { callback(ctx); },
    on(event, callback) { handlers.set(event, callback); },
  };
  const input = { serverName: 'example', url: '', scope: 'mcp', authorizationOrigins: [], allowInsecureLoopback: true };
  const config = Config(input);
  assert.equal(config.url.get(), '');
  try {
    await apply(ctx, config);
    assert.equal(tools.size, 4);
    assert.equal((await tools.get('mcp__example__oauth_status').execute()).status, 'not_configured');
    config.url = Config({ ...input, url: service.base + '/mcp' }).url;
    await handlers.get('settings/document-updated')();
    assert.equal(flows.size, 1);
    const login = await tools.get('mcp__example__oauth_login').execute();
    assert.equal(login.status, 'awaiting_browser');
    const response = await fetch(login.authorizationUrl, { redirect: 'manual' });
    await fetch(response.headers.get('location'));
    for (let i = 0; i < 100 && !tools.has('mcp__example__echo'); i++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal((await tools.get('mcp__example__oauth_status').execute()).status, 'connected');
    assert.equal((await tools.get('mcp__example__echo').execute({ text: 'DSH adapter' }, { signal: new AbortController().signal })).content[0].text, 'DSH adapter');
    assert.equal(service.writes, 0);
    await tools.get('mcp__example__oauth_logout').execute();
    assert.equal(tools.size, 4);
    assert.equal(records.size, 0);
    assert.notEqual(toolName('example', 'x.y'), toolName('example', 'x_y'));
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup?.();
    await service.close();
  }
});
