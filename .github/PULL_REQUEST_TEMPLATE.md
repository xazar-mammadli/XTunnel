## What and why

<!-- What does this change, and why? Link the issue it closes, if any: "Closes #123". -->

## How it was checked

<!-- Tests you added or ran, and what you tried between two machines. -->

## Checklist

- [ ] `go vet ./...` and `go test -race ./...` pass.
- [ ] Relay changes pass `npm run typecheck` and the relay tests in CONTRIBUTING.md.
- [ ] Nothing weakens the end-to-end encryption, the code check or the one-time codes.
- [ ] Wire format changes are described in `docs/PROTOCOL.md`.
- [ ] No new tracking or third-party services.
