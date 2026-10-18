# Contributing to XTunnel

Thanks for helping! Bug reports, ideas and code are all welcome.

## Before you start

- **Bugs and ideas:** open an issue with one of the templates. Search the existing issues first.
- **Larger changes:** open an issue to talk about it before you write the code, so no work goes to waste.
- **Security problems:** don't open a public issue. Report them privately, as [SECURITY.md](SECURITY.md) describes.

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Setting up

You need Go 1.25 or later, and Node.js for the relay.

```bash
git clone https://github.com/<your-account>/XTunnel.git
cd XTunnel
go vet ./...
go test -race ./...
```

The relay tests run against a local Worker:

```bash
cd relay/cloudflare && npm ci && npx wrangler dev --var UNPAIRED_TTL_MS:2000
XTUNNEL_TEST_RELAY=ws://127.0.0.1:8787 XTUNNEL_TEST_RELAY_SHORT_TTL=1 go test ./cmd/xtunnel -run Relay
```

## Rules for the code

XTunnel opens network paths into people's machines, so security comes before everything else.

- **End to end, always.** The relay and any TURN server only ever see ciphertext. Nothing may weaken the code check (PAKE), the certificate pinning or the one-time codes.
- **Only what was shared.** The sharing side dials only the ports it was given, on `127.0.0.1`.
- **No tracking.** No analytics and no new third-party services.
- **Clear words.** Output is short and plain, and every error says what to do next.
- **No comments in code.** Names and small functions carry the intent; wire formats live in [docs/PROTOCOL.md](docs/PROTOCOL.md).
- **Tests with every change.** `go vet ./...` and `go test -race ./...` pass.

## Pull requests

1. Fork the repository and create a branch from `master`.
2. Keep each pull request to one change, with a short description of what and why.
3. Make sure CI passes.
4. The maintainer reviews every pull request. Only the maintainer merges into `master` and publishes releases.

By contributing, you agree that your work is published under the [MIT License](LICENSE).

## Releases (maintainer)

Push an annotated `v<version>` tag. The release workflow builds every platform and publishes the archives with `SHA256SUMS`; the tag's message becomes the release notes. The public relay deploys from `relay/cloudflare` with `npx wrangler deploy`.
