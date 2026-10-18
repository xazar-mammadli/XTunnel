# Security policy

XTunnel opens a path into your machine, so security reports are taken seriously.

## Reporting a problem

Please don't open a public issue. Use **Report a vulnerability** on the [Security tab](https://github.com/xazar-mammadli/XTunnel/security/advisories/new) instead, which only the maintainer can see. Describe the problem, how to reproduce it, and what could go wrong.

You'll hear back within a week. Once a fix is released, the report is published, with credit to you if you like.

Examples of what to report:

- A way for the relay, a TURN server or anyone on the network to read, change or take over a tunnel.
- A way to pair without knowing the code, or to use a code twice.
- A way to reach a port on the sharing machine that wasn't shared.
- A way around the public relay's limits.

## Supported versions

Only the latest release gets fixes.

## Checking a release

Each release lists the SHA-256 of every archive in `SHA256SUMS`. To check a download:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```
