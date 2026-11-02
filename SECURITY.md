# Security

Report vulnerabilities privately through this repository's GitHub Security
Advisories reporting feature when available. Do not open a public issue containing
tokens, callback codes, user data or exploitable production details. If private
reporting is unavailable, request a private reporting channel without disclosing
the vulnerability in public.

## Boundary

This plugin runs as the local DSH host user. It trusts the configured MCP origin
and any explicitly configured authorization origins. All other discovered origins
and credential-request HTTP redirects are rejected. HTTPS is required except for
an explicit local fixture setting. There is no telemetry or shell execution.

Browser callbacks bind only to `127.0.0.1` on an OS-assigned port, with random path
and state, strict Host/Origin/query checks, single-use completion and timeout.
The official MCP SDK owns PKCE, issuer validation, resource binding and OAuth
token exchange. No arbitrary callback, TLS bypass or client-name impersonation
is offered.

Tokens are stored in DSH's credential service and are never exposed by management
tools. Credential protection and cross-process record locking depend on that
backend. A compromised OS account, DSH host or sibling plugin is outside this
plugin's isolation boundary. Do not use a shared profile for mutually untrusted
users.

Authentication does not authorize arbitrary business effects. The target service
and DSH tool policy remain responsible for access and operation confirmation.
Local logout clears credentials; service-side revocation is separate.

## Dependencies and artifacts

Runtime dependencies are the official MCP SDK and official DSH schema library.
DSH service peers are supplied by the host, not copied from a company repository.
The lockfile pins integrity hashes. Installation scripts are not required.
Publication must inspect the pack file list and scan tracked files for secrets.
No filled profiles, user data, company URLs or private backend source belong in
the public repository. Audit success is time-bound and does not replace review.
