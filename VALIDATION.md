# Desktop verification — 2026-11-02

Runtime code/tag: `v0.1.0-alpha.2`, commit
`aa456b24b3c792361004a694987c139f30a61c92`.

[CI checks](https://github.com/guoxianzhe/dsh-oauth/actions/runs/41441767647)
passed: syntax, 12 automated tests, dependency audit and package dry-run. The
reviewed local source tree equals the remote tree at that commit. Documentation
may advance independently after the tag; release tags are not rewritten.

Actual DSH Desktop `0.2.1-rc.2`, standard preset, against a local OAuth/MCP fixture:

| Check | Result |
| --- | --- |
| Install from a pinned public GitHub commit | Passed |
| Native configuration GUI | Passed |
| Browser code + PKCE callback | Passed |
| Authenticated read-only echo | Passed |
| MCP application error guidance and receipt | Passed; no grant operation followed the guidance |
| Cold restart with stored credentials | Connected and echoed without another browser sign-in |
| Automatic refresh with one-second access tokens | 4 refreshes observed in the final complete fixture |
| Business writes in the fixture | 0 |
| Logout and subsequent status | signed_out |
| Test cleanup | Tokens removed, mock URL cleared, HTTP-loopback option disabled |

The installed core sources, package manifest and patch matched the reviewed
files. The installed SDK was 2.4.0 with Zod 4.6.7. DSH profile dependency resolution
can differ from the development lockfile; audit the target profile separately.
The lockfile and CI are not a claim that every future installation is identical.

This is protocol and Desktop integration acceptance using simulated accounts.
No production account or business service was used. Other DSH versions, hosted
Web, and production MCP service authorization require separate acceptance.

The earlier `alpha.1` failed a Desktop cold-start check. It is not recommended;
its tag is retained rather than silently replaced.
