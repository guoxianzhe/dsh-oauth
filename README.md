# dsh-oauth

Browser OAuth for remote MCP services in **DeepSeek Harness Desktop**.
Independently maintained; not an official DeepSeek plugin.

Package identity: `@guoxianzhe/dsh-oauth` (GitHub repository: `guoxianzhe/dsh-oauth`).
Always install from the pinned GitHub source, not the unrelated npm package
`dsh-oauth`. Candidate `v0.1.0-alpha.1` failed a Desktop cold-start test; do not use it.
The fix is being validated as `v0.1.0-alpha.2`.

Configure an MCP URL, sign in in your browser, and use the service's tools in DSH.
No provider passwords or manually copied bearer tokens belong in plugin settings
or chat. This project is generic: it contains no company deployment configuration.

## Compatibility

- DSH Desktop's `0.2.1-rc.2` credential, authorization and tool service interfaces.
- Node.js 22.19 or later. Development checks use Node.js 24.
- Streamable HTTP MCP with OAuth authorization code + PKCE S256, dynamic client
  registration, public native clients and Bearer tokens.
- Server registration metadata uses `client_name: "DSH OAuth"`. The service must
  permit this client; a server restricted to another client will reject it.
- Hosted DSH Web is **not supported** by this desktop loopback flow. The browser
  and DSH host must run on the same computer.

## Install

During initial development, use a local checkout:

```sh
git clone https://github.com/guoxianzhe/dsh-oauth.git
cd dsh-oauth
npm ci --ignore-scripts
npm test
```

In DSH Desktop, open **Plugins → Add plugin** and enter the checkout's absolute
directory path. Keep the directory after installation. This GUI path does not
require switching the chat to Creator mode. Where Plugin Manager is available,
its `install_bundle` tool accepts the same directory as `target`.

There are no install scripts, shell-command executors or bundled service URLs.
For a reproducible installation, check out a reviewed commit; do not assume an
unreleased branch has been tested on your DSH version. The package is not yet
published to npm.

## Configure

Open the installed plugin's configuration. The browser form edits the URL, scope,
trusted origins and local-test setting. Namespace and timeout may be set by an
advanced custom bundle. Configuration fields:

| Field | Meaning |
| --- | --- |
| `serverName` | Unique namespace, 1–24 letters, digits, `_` or `-` |
| `url` | The service's HTTPS MCP endpoint |
| `scope` | Optional requested OAuth scope; otherwise SDK discovery selects it |
| `authorizationOrigins` | Additional trusted HTTPS authorization origins, if different from the MCP origin |
| `requestTimeoutMs` | Request timeout, 1,000–180,000 ms; default 30,000 |
| `allowInsecureLoopback` | Default false; HTTP loopback fixtures only, never a TLS bypass |

The installed bundle starts with an empty URL and makes no network requests.
The bundled settings page edits the default `dsh-oauth` entry. Advanced custom
bundles can use different configured plugin instances and `serverName` values
for multiple MCP servers.
The same namespace must not be configured by another MCP plugin.

Example configuration (replace the reserved example address):

```yaml
serverName: example
url: https://mcp.example.invalid/mcp
scope: mcp
authorizationOrigins: []
```

Discovery cannot silently authorize another network origin. If an authorization
server is hosted separately, first verify it with the service owner, then add
its exact origin to `authorizationOrigins`. Redirects in credential-bearing HTTP
requests are rejected. Do not disable TLS verification to make a service work.

## Sign in and use

Ask DSH to call `mcp__example__oauth_login`. Open the returned authorization link,
sign in and approve the scope on the service's page, then return to DSH and call
`mcp__example__oauth_status`. Do not paste credentials or callback URLs into chat.
If DSH exposes credential authorization flows in its settings, **MCP: example**
offers the same browser sign-in outside the chat tool path.

After authentication, remote tools appear as `mcp__example__<tool>`. First perform
an appropriate read-only check. DSH's normal tool permissions still apply; login
does not confirm a business operation. Each chat preset must expose the plugin's
tools; installation alone is not proof that every preset can use them.

Management tools:

- `oauth_status`: status only, never tokens.
- `oauth_login`: explicit browser sign-in; one pending attempt per instance.
- `oauth_reconnect`: reconnect with existing credentials, without calling a business tool.
- `oauth_logout`: disconnect and remove this plugin's local credential record.

MCP application error content is returned to the chat as a failed tool result,
including the service's guidance and receipts. OAuth/HTTP exception bodies are
redacted. Choose trusted MCP services: their tool output is business data supplied
to the model, not a secret-storage channel.

On restart, the plugin reconnects with stored credentials. Expiring access tokens
are refreshed under the credential store's record lock. Scope expansion requires
a fresh user sign-in; it is not silently granted. Network-uncertain business calls
are not automatically retried. Check the service's original receipt before
retrying a write.

## Credential storage and logout

Credentials live only in DSH's credential record service, partitioned by server
URL, namespace, configured scope and trusted authorization origins. The plugin
does not implement its own token file or log upstream OAuth bodies. PKCE verifier
and callback state are memory-only and expire with the sign-in attempt.

Storage protection depends on the DSH credential backend; the default local
backend is not a promise of OS-keychain encryption. Protect the DSH profile and
its backups. This plugin does not provide isolation from other plugins or
processes running as the same OS user.

Local logout does **not** revoke the service-side grant. Revoke it in the service
console when required. Changing configuration selects a different credential
record; log out the old configuration before removing it to avoid orphaned grants.

## Limits and verification

This first release handles text, structured results and resource links. Binary
images/audio, resource read APIs, task-only tools, pre-registered confidential
clients, DPoP and hosted-web callbacks are not implemented. A binary response is
reported as unsupported after the call; do not replay a write to obtain it again.
It registers at most 256 tools and caps JSON responses at 4 MiB. Reconnect is
explicit after a broken connection; there is no background retry loop for tools.

```sh
npm ci --ignore-scripts
npm run check
npm test
npm audit
npm pack --dry-run --ignore-scripts
```

Tests drive the real official MCP SDK against a local OAuth/MCP fixture. They
cover PKCE, state and issuer checks, refresh rotation, persistence, logout,
credential partitioning and network-origin restrictions. Fixture success is not
production-service acceptance. Desktop installation and real-service results
must be recorded separately.

Protocol reference: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
