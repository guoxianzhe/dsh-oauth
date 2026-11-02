import { createHash } from 'node:crypto';
import z from '@deepseek-ai/schemastery';
import { OAuthConnection } from './oauth.js';
import { credentialId, failureKind, protocolGuidance, SafeError } from './security.js';

export const name = 'dsh-oauth';
export const inject = ['tools', 'credentials'];
export const Config = z.object({
  serverName: z.string().pattern(/^[A-Za-z0-9_-]{1,24}$/).default('example'),
  url: z.string().default('').volatile(),
  scope: z.string().default('').volatile(),
  authorizationOrigins: z.array(String).default([]).volatile(),
  requestTimeoutMs: z.number().step(1).min(1000).max(180000).default(30000).volatile(),
  allowInsecureLoopback: z.boolean().default(false).volatile(),
});

export function toolName(serverName, rawName) {
  const full = `mcp__${serverName}__${rawName}`;
  if (/^[A-Za-z0-9_-]{1,64}$/.test(full)) return full;
  return `${full.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 47)}_${createHash('sha256').update(full).digest('hex').slice(0, 16)}`;
}

const jsonOutput = {
  schema: {},
  render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
};

function remoteDefinition(connection, serverName, tool) {
  return {
    name: toolName(serverName, tool.name), description: tool.description ?? '',
    parameters: tool.inputSchema,
    output: {
      schema: {},
      render: (_args, value) => value.content.map(block => {
        if (block.type === 'text') return block;
        return { type: 'text', text: JSON.stringify(block) };
      }),
    },
    async execute(args, exec) {
      try {
      if (tool.execution?.taskSupport === 'required') throw new SafeError('Task-only tools are not supported in this release.');
      const result = await connection.call(tool, args, exec.signal);
      if (result.isError) {
        // MCP application errors intentionally carry caller-facing guidance and
        // receipts. Preserve them; only OAuth/HTTP exception bodies are hidden.
        const failure = { isError: true, content: result.content.filter(block => block.type === 'text' || block.type === 'resource_link'),
          ...(result.structuredContent === undefined ? {} : { structuredContent: result.structuredContent }) };
        throw new SafeError(`MCP tool error: ${JSON.stringify(failure).slice(0, 65536)}`);
      }
      // Refuse unsupported binary output rather than exposing base64 to the LLM.
      if (result.content.some(block => block.type === 'image' || block.type === 'audio' || block.type === 'resource' && block.resource?.blob)) {
        throw new SafeError('This release supports text, structured data and resource links; binary output is unsupported. The remote call ran: do not replay a write.');
      }
      return result;
      } catch (error) {
        const guidance = protocolGuidance(error, connection.config);
        if (guidance) throw new SafeError(`MCP authorization guidance: ${JSON.stringify(guidance)}`);
        throw new SafeError(error instanceof SafeError ? error.message : 'MCP call failed. Its outcome may be unknown; inspect the original receipt before retrying a write.');
      }
    },
  };
}

export async function apply(ctx, config) {
  const serverName = config.serverName ?? 'example';
  if (!/^[A-Za-z0-9_-]{1,24}$/.test(serverName)) throw new SafeError('Invalid MCP server name.');
  let connection;
  let authorization;
  let disposeFlow;
  let signature;
  let configurationError;
  let configuring = Promise.resolve();
  let toolDisposers = [];
  const clearTools = () => { for (const dispose of toolDisposers) dispose(); toolDisposers = []; };
  const manage = (operation, description, execute) => ctx.tools.register({
    name: `mcp__${serverName}__oauth_${operation}`, description,
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: jsonOutput,
    async execute() {
      try { return await execute(); }
      catch (error) {
        // No upstream error messages/HTTP bodies: they may contain credentials.
        throw new SafeError(error instanceof SafeError ? error.message : `OAuth operation failed (${connection?.phase ?? 'configuration'}/${failureKind(error)}). Check the service and plugin configuration; credentials and upstream responses are not logged.`);
      }
    },
  });
  const mountFlow = () => {
    disposeFlow?.(); disposeFlow = undefined;
    if (!authorization || !connection) return;
    const c = connection;
    disposeFlow = authorization.registerFlow({
      key: c.key, label: `MCP: ${serverName}`, methods: [{ id: 'oauth', label: 'Sign in with browser' }],
      async run(session) {
        const attempt = await c.startLogin();
        const abort = () => { void c.logout().catch(() => { c.status = 'sign_out_failed'; }); };
        session.signal.addEventListener('abort', abort, { once: true });
        try {
          if (session.signal.aborted) abort();
          session.notify({ message: 'Sign in in your browser, then return to DSH.', url: attempt.authorizationUrl });
          await attempt.finished;
        } finally { session.signal.removeEventListener('abort', abort); }
      },
    });
  };
  const read = value => typeof value?.get === 'function' ? value.get() : value;
  const configure = () => {
    const snapshot = { serverName, url: read(config.url), scope: read(config.scope),
      authorizationOrigins: [...(read(config.authorizationOrigins) ?? [])],
      requestTimeoutMs: read(config.requestTimeoutMs), allowInsecureLoopback: read(config.allowInsecureLoopback) };
    const next = JSON.stringify(snapshot);
    if (next === signature) return configuring;
    signature = next;
    configuring = configuring.then(async () => {
      disposeFlow?.(); disposeFlow = undefined;
      await connection?.dispose(); connection = undefined;
      configurationError = undefined;
      if (!snapshot.url) return;
      // Early local candidates used a bare digest, which is not a valid DSH
      // credential id when it begins with a digit. Remove only this exact
      // malformed key owned by this configured service; never enumerate secrets.
      const legacyKey = credentialId(snapshot).replace('/server-', '/');
      if (/^dsh-oauth\/[0-9]/.test(legacyKey)) await ctx.credentials.deleteRecord(legacyKey);
      const c = new OAuthConnection(snapshot, ctx.credentials);
      connection = c;
      c.onDisconnected = () => { if (connection === c) clearTools(); };
      c.onConnected = async (_client, tools) => {
        if (connection !== c) throw new SafeError('The MCP configuration changed. Reconnect.');
        const definitions = tools.map(tool => remoteDefinition(c, serverName, tool));
        if (tools.length > 256) throw new SafeError('This release supports at most 256 tools per server.');
        const names = definitions.map(def => def.name);
        if (new Set(names).size !== names.length || tools.some(t => /^oauth_(login|status|logout|reconnect)$/.test(t.name))) {
          throw new SafeError('MCP server returned duplicate or reserved tool names.');
        }
        clearTools();
        try { for (const definition of definitions) toolDisposers.push(ctx.tools.register(definition)); }
        catch { clearTools(); throw new SafeError('The MCP tool schema or registration is unsupported.'); }
      };
      mountFlow();
      try { await c.connect(); } catch { c.status = 'sign_in_required'; }
    }).catch(error => { configurationError = failureKind(error); });
    return configuring;
  };
  ctx.inject(['authorization'], inner => {
    authorization = inner.authorization; mountFlow();
    inner.effect(() => () => { disposeFlow?.(); disposeFlow = undefined; authorization = undefined; }, 'dsh-oauth.authorization');
  });
  ctx.on('settings/document-updated', () => configure(), { global: true });
  ctx.effect(() => async () => { disposeFlow?.(); await configuring; await connection?.dispose(); }, 'dsh-oauth.connection');
  const requireConnection = () => {
    if (configurationError) throw new SafeError(`Configuration could not be applied (${configurationError}). Check the plugin settings and credential backend.`);
    if (!connection) throw new SafeError('Set the MCP HTTPS URL in this plugin’s settings first.');
    return connection;
  };
  const disposers = [
    manage('status', 'Read this MCP OAuth connection status; never returns credentials.', () => ({ serverName, status: connection?.status ?? (configurationError ? 'configuration_failed' : 'not_configured') })),
    manage('login', 'Start browser sign-in for this configured MCP service when the user requests it. Return the URL for the human to open; never ask for tokens or passwords.', async () => {
      const c = requireConnection();
      const attempt = await c.startLogin();
      return { status: 'awaiting_browser', authorizationUrl: attempt.authorizationUrl,
        next: 'Open this URL, sign in and approve the requested scope, then ask for oauth_status. Do not paste credentials or the callback URL into chat.' };
    }),
    manage('reconnect', 'Reconnect this configured MCP service using previously authorized credentials. Does not invoke business tools.', async () => {
      const c = requireConnection(); await c.connect(); return { status: c.status };
    }),
    manage('logout', 'When the user explicitly requests logout, disconnect and delete this plugin’s local credential record. This does not revoke the server-side grant.', async () => {
      const c = requireConnection(); await c.logout(); return { status: c.status };
    }),
  ];
  ctx.effect(() => () => { clearTools(); for (const dispose of disposers) dispose(); }, 'dsh-oauth.tools');
  await configure();
}
