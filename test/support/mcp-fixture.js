import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';

export async function fixture() {
  const clients = new Map(), codes = new Map();
  let base, refreshes = 0, writes = 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, base);
    const send = (status, data, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(JSON.stringify(data));
    };
    const body = async () => { const chunks = []; for await (const c of req) chunks.push(c); return Buffer.concat(chunks).toString(); };
    if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) return send(200, { resource: base + '/mcp', authorization_servers: [base], scopes_supported: ['mcp'] });
    if (url.pathname === '/.well-known/oauth-authorization-server') return send(200, {
      issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token',
      registration_endpoint: base + '/register', response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
      scopes_supported: ['mcp'], authorization_response_iss_parameter_supported: true,
    });
    if (url.pathname === '/register') {
      const metadata = JSON.parse(await body());
      assert.equal(metadata.client_name, 'DSH OAuth');
      assert.equal(metadata.application_type, 'native');
      const client_id = `client-${clients.size}`;
      clients.set(client_id, metadata); return send(201, { ...metadata, client_id });
    }
    if (url.pathname === '/authorize') {
      const p = url.searchParams;
      const metadata = clients.get(p.get('client_id'));
      assert.ok(metadata.redirect_uris.includes(p.get('redirect_uri')));
      assert.equal(p.get('code_challenge_method'), 'S256');
      assert.equal(p.get('resource'), base + '/mcp');
      const code = 'code-' + codes.size;
      codes.set(code, { challenge: p.get('code_challenge'), redirect: p.get('redirect_uri') });
      const callback = new URL(p.get('redirect_uri'));
      callback.searchParams.set('state', p.get('state'));
      callback.searchParams.set('code', code); callback.searchParams.set('iss', base);
      res.writeHead(302, { location: callback.href }); return res.end();
    }
    if (url.pathname === '/token') {
      const p = new URLSearchParams(await body());
      if (p.get('grant_type') === 'authorization_code') {
        const code = codes.get(p.get('code')); codes.delete(p.get('code'));
        assert.ok(code);
        assert.equal(createHash('sha256').update(p.get('code_verifier')).digest('base64url'), code.challenge);
        assert.equal(p.get('redirect_uri'), code.redirect);
      } else {
        assert.equal(p.get('refresh_token'), `refresh-${refreshes}`); refreshes++;
      }
      return send(200, { access_token: `access-${refreshes}`, refresh_token: `refresh-${refreshes}`, expires_in: 3600, token_type: 'Bearer', scope: 'mcp' });
    }
    if (url.pathname === '/mcp') {
      if (req.headers.authorization !== `Bearer access-${refreshes}`) return send(401, { error: 'unauthorized' }, {
        'www-authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`,
      });
      if (req.method !== 'POST') { res.writeHead(405); return res.end(); }
      const message = JSON.parse(await body());
      if (message.id === undefined) { res.writeHead(202); return res.end(); }
      let result;
      if (message.method === 'initialize') result = { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } };
      else if (message.method === 'tools/list') result = { tools: [{ name: 'echo', description: 'Echo text', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } }, { name: 'write', inputSchema: { type: 'object', properties: {} } }] };
      else if (message.method === 'tools/call') {
        if (message.params.name === 'write') writes++;
        result = { content: [{ type: 'text', text: message.params.arguments?.text ?? 'written' }] };
      } else return send(400, { error: 'unsupported_method' });
      return send(200, { jsonrpc: '2.0', id: message.id, result });
    }
    return send(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  return { base, get refreshes() { return refreshes; }, get writes() { return writes; },
    close: () => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); } };
}
