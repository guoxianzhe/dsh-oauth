import { auth, Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { credentialId, endpoint, LoginRequired, loopback, restrictedFetch, SafeError } from './security.js';

// One transaction per credential serializes refresh rotation across DSH hosts.
// ponytail: it also serializes tool requests for that credential; replace with
// a durable refresh lease if parallel calls become a measured requirement.
export class OAuthConnection {
  constructor(config, credentials, { fetchImpl = fetch } = {}) {
    this.config = { authorizationOrigins: [], scope: '', requestTimeoutMs: 30_000, ...config };
    this.credentials = credentials;
    this.key = credentialId(this.config);
    this.controller = new AbortController();
    this.fetchImpl = fetchImpl;
    this.fetch = restrictedFetch(this.config, fetchImpl, this.controller.signal);
    this.client = undefined;
    this.pending = undefined;
    this.loginGeneration = 0;
    this.starting = false;
    this.status = 'disconnected';
    this.phase = 'idle';
    this.onConnected = async () => {};
    this.onDisconnected = () => {};
  }

  async transaction(operation, signal = this.controller.signal) {
    let result, failure, failedPhase;
    this.phase = 'credential_lock';
    await this.credentials.modifyRecord(this.key, async current => {
      this.controller.signal.throwIfAborted();
      signal.throwIfAborted();
      const data = structuredClone(current?.payload ?? {});
      const provider = this.provider(data);
      this.activeData = data;
      try { result = await operation(provider, data); } catch (error) { failure = error; failedPhase = this.phase; }
      finally { this.activeData = undefined; }
      this.controller.signal.throwIfAborted();
      signal.throwIfAborted();
      // The SDK includes absent optional fields as undefined; DSH's credential
      // backend accepts JSON values only. Keep exactly the JSON representation.
      this.phase = 'storing_credentials';
      const payload = JSON.parse(JSON.stringify(data, (_key, value) => {
        if (typeof value === 'number' && !Number.isFinite(value)) throw new SafeError('Invalid OAuth state.');
        return value;
      }));
      this.lastData = payload;
      if (JSON.stringify(current?.payload ?? {}) === JSON.stringify(payload)) return undefined;
      return { kind: 'grant', payload };
    });
    this.phase = failedPhase ?? 'credentials_stored';
    if (failure) throw failure;
    return result;
  }

  provider(data, attempt) {
    const owner = this;
    const initial = data;
    data = new Proxy({}, {
      get: (_target, key) => (owner.activeData ?? owner.lastData ?? initial)[key],
      set: (_target, key, value) => {
        if (!owner.activeData) throw new SafeError('Credential update requires a new explicit connection operation.');
        owner.activeData[key] = value; return true;
      },
      deleteProperty: (_target, key) => {
        if (!owner.activeData) throw new SafeError('Credential update requires a new explicit connection operation.');
        delete owner.activeData[key]; return true;
      },
    });
    const config = this.config;
    const issuerMatches = (value, context) => !context?.issuer || !value?.issuer || value.issuer === context.issuer;
    return {
      get redirectUrl() { return data.redirectUrl; },
      get clientMetadata() { return {
        client_name: 'DSH OAuth', application_type: 'native',
        redirect_uris: data.redirectUrl ? [data.redirectUrl] : [],
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
        token_endpoint_auth_method: 'none', ...(config.scope ? { scope: config.scope } : {}),
      }; },
      state: () => { if (!attempt) throw new LoginRequired(); return attempt.state; },
      clientInformation: context => issuerMatches(data.client, context) ? data.client : undefined,
      saveClientInformation: value => { data.client = value; this.phase = 'client_registered'; },
      tokens: context => issuerMatches(data.tokens, context) ? data.tokens : undefined,
      saveTokens: value => {
        if (value.token_type?.toLowerCase() !== 'bearer') throw new SafeError('Only Bearer tokens are supported in this release.');
        data.tokens = value;
        data.expiresAt = value.expires_in === undefined ? undefined : Date.now() + value.expires_in * 1000;
      },
      redirectToAuthorization: url => {
        if (!attempt) throw new LoginRequired();
        const parsed = endpoint(url.origin, config.allowInsecureLoopback);
        const allowed = new Set([new URL(config.url).origin, ...config.authorizationOrigins.map(v => new URL(v).origin)]);
        if (!allowed.has(parsed.origin) || url.username || url.password || url.hash) throw new SafeError('Untrusted authorization origin.');
        attempt.authorizationUrl = url.href;
        this.phase = 'authorization_url_ready';
      },
      saveCodeVerifier: value => { if (!attempt) throw new LoginRequired(); attempt.verifier = value; this.phase = 'pkce_ready'; },
      codeVerifier: () => { if (!attempt?.verifier) throw new SafeError('Sign-in expired.'); return attempt.verifier; },
      saveDiscoveryState: value => { data.discovery = value; this.phase = 'discovery_complete'; },
      discoveryState: () => data.discovery,
      invalidateCredentials: scope => {
        if (scope === 'all' || scope === 'client') delete data.client;
        if (scope === 'all' || scope === 'tokens') { delete data.tokens; delete data.expiresAt; }
        if (scope === 'all' || scope === 'discovery') delete data.discovery;
        if (attempt && (scope === 'all' || scope === 'verifier')) attempt.verifier = undefined;
      },
    };
  }

  async startLogin() {
    if (this.pending) {
      if (!this.pending.authorizationUrl) throw new SafeError('A sign-in is already starting.');
      return { authorizationUrl: this.pending.authorizationUrl, finished: this.pending.finished };
    }
    if (this.starting) throw new SafeError('A sign-in is already starting.');
    this.starting = true;
    const generation = this.loginGeneration;
    try { return await this.prepareLogin(generation); }
    finally { this.starting = false; }
  }

  async prepareLogin(generation) {
    await this.disconnect();
    if (generation !== this.loginGeneration) throw new SafeError('Sign-in cancelled.');
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, this.controller.signal]);
    const callback = await loopback({ signal });
    if (generation !== this.loginGeneration) { callback.cancel(); throw new SafeError('Sign-in cancelled.'); }
    const attempt = { ...callback, cancel: () => { controller.abort(); callback.cancel(); } };
    const fetchFn = restrictedFetch(this.config, this.fetchImpl, signal);
    this.pending = attempt;
    this.status = 'authorizing';
    try {
      await this.transaction(async (_provider, data) => {
        // A newly allocated redirect URI must receive a new DCR registration.
        delete data.client; delete data.discovery;
        data.redirectUrl = callback.redirectUrl;
        const provider = this.provider(data, attempt);
        this.phase = 'oauth_discovery';
        await auth(provider, { serverUrl: this.config.url, scope: this.config.scope || undefined,
          forceReauthorization: true, fetchFn });
        if (!attempt.authorizationUrl) throw new SafeError('The server did not provide an interactive sign-in URL.');
      }, signal);
      attempt.finished = (async () => {
        try {
          const { code, iss } = await callback.result;
          await this.transaction(async (_provider, data) => {
            if (this.pending !== attempt) throw new SafeError('Sign-in cancelled.');
            await auth(this.provider(data, attempt), { serverUrl: this.config.url, authorizationCode: code,
              iss, scope: this.config.scope || undefined, fetchFn });
          }, signal);
          if (this.pending !== attempt) throw new SafeError('Sign-in cancelled.');
          await this.connect();
        } finally {
          attempt.verifier = undefined; callback.cancel();
          if (this.pending === attempt) this.pending = undefined;
        }
      })();
      attempt.finished.catch(() => { this.status = 'sign_in_failed'; });
      return { authorizationUrl: attempt.authorizationUrl, finished: attempt.finished };
    } catch (error) {
      attempt.verifier = undefined;
      this.pending = undefined; attempt.cancel(); this.status = 'sign_in_failed';
      throw error;
    }
  }

  async connect() {
    await this.disconnect();
    await this.transaction(async (provider, data) => {
      if (!data.tokens) throw new LoginRequired();
      if (data.expiresAt !== undefined && data.expiresAt <= Date.now() + 30_000) {
        await auth(provider, { serverUrl: this.config.url, scope: this.config.scope || undefined, fetchFn: this.fetch });
      }
      const client = new Client({ name: 'dsh-oauth', version: '0.1.0-alpha.3' });
      const transport = new StreamableHTTPClientTransport(new URL(this.config.url), {
        authProvider: provider, fetch: this.fetch, onInsufficientScope: 'throw',
      });
      try {
        await client.connect(transport);
        const { tools } = await client.listTools();
        await this.onConnected(client, tools);
        this.client = client;
        this.status = 'connected';
      } catch (error) { await client.close().catch(() => {}); this.status = 'disconnected'; throw error; }
    });
  }

  async call(tool, args, signal) {
    if (!this.client) throw new LoginRequired();
    return this.transaction(async (provider, data) => {
      if (data.expiresAt !== undefined && data.expiresAt <= Date.now() + 30_000) {
        await auth(provider, { serverUrl: this.config.url, scope: this.config.scope || undefined, fetchFn: this.fetch });
      }
      // The transport reads the same record object; never retry network-uncertain calls.
      return this.client.callTool({ name: tool.name, arguments: args }, {
        signal, timeout: this.config.requestTimeoutMs, toolDefinition: tool,
      });
    });
  }

  async disconnect() {
    const client = this.client; this.client = undefined;
    this.onDisconnected();
    await client?.close().catch(() => {});
    this.status = 'disconnected';
  }

  async logout() {
    this.loginGeneration++;
    const pending = this.pending; this.pending = undefined;
    pending?.cancel(); await pending?.finished?.catch(() => {});
    await this.disconnect();
    await this.credentials.deleteRecord(this.key);
    this.status = 'signed_out';
  }

  async dispose() {
    this.controller.abort(); this.pending?.cancel();
    await this.pending?.finished?.catch(() => {});
    await this.disconnect();
  }
}
