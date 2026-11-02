import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { ProtocolError } from '@modelcontextprotocol/client';

export class SafeError extends Error {}
// Only explicit MCP recovery metadata is caller-facing; never expose HTTP bodies,
// exception messages, arbitrary error data, or links outside configured origins.
export function protocolGuidance(error, config) {
  const data = error?.data;
  if (!(error instanceof ProtocolError) || error.code !== -32001 || !data ||
      !/^[A-Z][A-Z0-9_]{0,95}$/.test(data.reasonCode ?? '')) return;
  const text = value => typeof value === 'string' && value.length <= 1000 && !/[\u0000-\u001f]/.test(value);
  const action = data.nextAction;
  if (!text(data.title) || !Array.isArray(data.steps) || data.steps.length > 10 ||
      !data.steps.every(text) || !text(action?.label) || !text(action?.type)) return;
  let url;
  try { url = new URL(action.url); } catch { return; }
  const origins = new Set([new URL(config.url).origin, ...(config.authorizationOrigins ?? [])]);
  if (!origins.has(url.origin) || url.username || url.password || url.hash ||
      [...url.searchParams.keys()].some(key => /^(?:.*token|.*secret|password|code|state|api[_-]?key)$/i.test(key))) return;
  const result = { reasonCode: data.reasonCode, title: data.title, steps: data.steps,
    nextAction: { type: action.type, label: action.label, url: url.href } };
  if (typeof data.traceId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(data.traceId)) result.traceId = data.traceId;
  return JSON.stringify(result).length <= 8192 ? result : undefined;
}
export function failureKind(error) {
  const allowed = new Set(['Error', 'TypeError', 'ReferenceError', 'AbortError', 'OperationError',
    'SdkHttpError', 'OAuthError', 'RegistrationRejectedError', 'InvalidGrantError', 'AuthorizationServerMismatchError']);
  return allowed.has(error?.name) ? error.name : 'OtherError';
}
export class LoginRequired extends SafeError {
  constructor() { super('Browser sign-in required. Start oauth_login or use the DSH credential authorization page.'); }
}

export function endpoint(value, allowInsecureLoopback = false) {
  let url;
  try { url = new URL(value); } catch { throw new SafeError('Enter a valid MCP URL in plugin settings.'); }
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.username || url.password || url.hash || url.search ||
      (url.protocol !== 'https:' && !(allowInsecureLoopback && loopback && url.protocol === 'http:'))) {
    throw new SafeError('Use HTTPS without credentials, query parameters or fragments. HTTP loopback is test-only and must be explicitly enabled.');
  }
  return url;
}

export function credentialId(config) {
  return `dsh-oauth/server-${createHash('sha256').update(JSON.stringify({
    name: config.serverName, url: config.url, scope: config.scope ?? '',
    origins: [...config.authorizationOrigins].sort(),
  })).digest('hex')}`;
}

// Every network destination is explicitly configured. Discovery is never a grant
// to forward credentials to an arbitrary origin or follow HTTP redirects.
export function restrictedFetch(config, fetchImpl = fetch, signal) {
  const resource = endpoint(config.url, config.allowInsecureLoopback);
  const origins = new Set([resource.origin, ...config.authorizationOrigins.map(value => {
    const url = endpoint(value, config.allowInsecureLoopback);
    if (url.pathname !== '/') throw new SafeError('Authorization origins must not contain a path.');
    return url.origin;
  })]);
  return async (input, init = {}) => {
    let url;
    try { url = new URL(input instanceof Request ? input.url : input); } catch { throw new SafeError('Invalid OAuth endpoint.'); }
    if (url.username || url.password || url.hash || !origins.has(url.origin)) {
      throw new SafeError('OAuth discovered an untrusted origin. Confirm the issuer and add its HTTPS origin to authorizationOrigins in plugin settings.');
    }
    const response = await fetchImpl(input, {
      ...init, redirect: 'error',
      signal: AbortSignal.any([signal, init.signal, input instanceof Request ? input.signal : undefined,
        AbortSignal.timeout(config.requestTimeoutMs ?? 30_000)].filter(Boolean)),
    });
    const type = response.headers.get('content-type') ?? '';
    if (response.body && /(?:application\/(?:[^;]+\+)?json|text\/plain)/i.test(type)) {
      let bytes = 0;
      const body = response.body.pipeThrough(new TransformStream({
        transform(chunk, controller) {
          bytes += chunk.byteLength;
          if (bytes > 4 * 1024 * 1024) throw new SafeError('MCP or OAuth JSON response exceeded 4 MiB.');
          controller.enqueue(chunk);
        },
      }));
      return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
    }
    return response;
  };
}

export async function loopback({ timeoutMs = 180_000, signal } = {}) {
  const state = randomBytes(32).toString('base64url');
  const path = `/callback/${randomBytes(24).toString('base64url')}`;
  let finish;
  let closed = false;
  let timer;
  const result = new Promise((resolve, reject) => { finish = (error, value) => error ? reject(error) : resolve(value); });
  // Attach immediately: cancellation may precede the caller awaiting the result.
  result.catch(() => {});
  let origin;
  const server = createServer({ maxHeaderSize: 8192 }, (req, res) => {
    const reply = (status, text) => {
      res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
        'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'" });
      res.end(text);
    };
    if (req.method !== 'GET' || req.headers.host !== new URL(origin).host ||
        req.url.length > 8192 || req.headers.origin && req.headers.origin !== origin) {
      return reply(400, 'Invalid callback.');
    }
    const url = new URL(req.url, origin);
    if (url.pathname !== path || url.origin !== origin) return reply(404, 'Not found.');
    for (const key of ['state', 'code', 'error', 'iss']) {
      if (url.searchParams.getAll(key).length > 1) return reply(400, 'Invalid callback.');
    }
    const given = url.searchParams.get('state') ?? '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(given) || !timingSafeEqual(Buffer.from(given), Buffer.from(state))) {
      return reply(400, 'Invalid callback state.');
    }
    if (closed) return reply(410, 'This sign-in has ended.');
    if (url.searchParams.has('error')) {
      reply(400, 'Authorization was declined. Return to DSH.');
      return cancel(new SafeError('Authorization declined.'));
    }
    const code = url.searchParams.get('code');
    if (!code || code.length > 4096) return reply(400, 'Invalid callback.');
    reply(200, 'Authorization response received. Return to DSH to check completion.');
    close();
    finish(undefined, { code, iss: url.searchParams.get('iss') ?? undefined });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  const close = () => {
    closed = true; clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    server.close(); server.closeIdleConnections();
  };
  const cancel = (error = new SafeError('Sign-in cancelled.')) => { if (!closed) { close(); finish(error); } };
  const abort = () => cancel(new SafeError('Sign-in cancelled.'));
  if (signal?.aborted) throw new SafeError('Sign-in cancelled.');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  signal?.addEventListener('abort', abort, { once: true });
  timer = setTimeout(() => cancel(new SafeError('Sign-in timed out. Start a new sign-in.')), timeoutMs);
  timer.unref();
  if (signal?.aborted) abort();
  return { redirectUrl: origin + path, state, result, cancel };
}
