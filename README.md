# xtunnel

Peer-to-peer encrypted TCP port forwarding across NATs. Two machines on
different networks establish a direct, end-to-end-encrypted tunnel — like
WebRTC, but for forwarding ports from a terminal.

- **Direct P2P** via ICE/STUN hole punching; falls back to a relay when hole
  punching fails.
- **End-to-end encrypted** with QUIC/TLS 1.3 and certificate-fingerprint
  pinning. The rendezvous server and relay only ever see ciphertext.
- **Pair with one short code** through a public signaling broker (no server to
  run), a self-hosted rendezvous server, or fully offline copy-paste codes.
- **Single static binary**, no CGo. Runs on Linux, macOS and Windows —
  x86-64 and arm64.

Built on [pion/ice](https://github.com/pion/ice) for NAT traversal and
[quic-go](https://github.com/quic-go/quic-go) for the encrypted, multiplexed
data plane.

## Install

Download a release archive for your platform from the releases page, or build
from source (Go 1.26+):

```sh
go install github.com/xazar/xtunnel/cmd/xtunnel@latest
# for the optional self-hosted server:
go install github.com/xazar/xtunnel/cmd/xtunneld@latest
```

## Usage

There are three ways to pair the two sides. All give the same encrypted tunnel;
they differ only in how the two peers first find each other.

### One-code pairing (no server to run)

The side that shares a port runs `offer` and gets one short code; the other
runs `answer` with it. Signaling goes through a public pub/sub broker
(ntfy.sh by default) — you run nothing, and the broker only ever sees
ciphertext (PAKE keeps it from reading or MITM-ing the tunnel).

```sh
# Machine A — share local port 5432 (e.g. Postgres):
$ xtunnel offer --expose 5432
pairing code — run this on the other machine:

    xtunnel answer apple-river-cedar-otter-maple-delta -L <localport>:5432

# Machine B — forward local port 15432 to A's port 5432:
$ xtunnel answer apple-river-cedar-otter-maple-delta -L 15432:5432
```

Now on machine B, `psql -h 127.0.0.1 -p 15432` reaches A's Postgres.

The code is one-time and high-entropy; exchange it reasonably promptly (NAT
bindings go stale). Point `--signal-url https://your-ntfy` at a different broker
if you like. This mode has no relay fallback (STUN only); use rendezvous mode
below if you need to traverse symmetric NATs.

### Offline copy-paste (no network at all for signaling)

Add `--offline` to both sides to exchange two base64 blobs by hand — no broker,
useful when even a public broker is unreachable:

```sh
$ xtunnel offer --offline --expose 5432       # prints xt1_… ; paste B's reply back
$ xtunnel answer --offline xt1_… -L 15432:5432 # prints xt1_… reply to send to A
```

### Rendezvous mode (self-hosted server)

Run `xtunneld` once on a small VPS, then peers meet via a short room code. The
server relays only encrypted signaling; the tunnel itself is direct P2P (or
relayed through the server's built-in TURN when hole punching fails).

```sh
# On your server (once):
$ xtunneld --listen :443 --tls-cert cert.pem --tls-key key.pem \
           --turn-public-ip 203.0.113.7 --turn-secret "$(openssl rand -hex 32)"

# Machine A:
$ xtunnel host --server wss://tunnel.example.com --expose 5432
room code — give it to the joining side:
42731-apple-river-cedar

# Machine B:
$ xtunnel join 42731-apple-river-cedar --server wss://tunnel.example.com -L 15432:5432
```

In rendezvous mode the tunnel **auto-reconnects**: if the connection drops, the
peers re-establish it over the same room without a new code (disable with
`--retry=false`).

### Forward specs (`-L`)

| Form | Meaning |
| --- | --- |
| `-L 8080` | `127.0.0.1:8080` → peer's port `8080` |
| `-L 15432:5432` | `127.0.0.1:15432` → peer's port `5432` |
| `-L 0.0.0.0:8080:80` | `0.0.0.0:8080` → peer's port `80` |

Repeat `-L` (and `--expose`) to forward several ports over one tunnel.

## How it works

```
                    ┌─────────────┐
   room code /      │  xtunneld   │   (rendezvous mode only)
   PAKE handshake   │  mailbox +  │
        ┌──────────▶│  STUN/TURN  │◀──────────┐
        │           └─────────────┘           │
        │            signaling only           │
   ┌────┴────┐      (ciphertext relay)   ┌────┴────┐
   │ xtunnel │◀───── direct P2P QUIC ───▶│ xtunnel │
   │  (host) │       (TLS 1.3, E2E)      │ (joiner)│
   └─────────┘                           └─────────┘
```

1. **Pairing.** In broker and rendezvous modes both peers run a PAKE (SPAKE2
   over P-256) keyed by the code, whose secret is never sent to the broker or
   server — so a malicious or compromised intermediary cannot derive the
   session key or MITM the tunnel, and online guessing is bounded to one
   attempt per code. In offline mode the copy-paste channel is the trust
   anchor.
2. **NAT traversal.** Each peer gathers ICE candidates (host, STUN-reflexive,
   TURN-relay) and they run connectivity checks to find a working path.
3. **Encryption.** QUIC/TLS 1.3 runs over the chosen path. Each side pins the
   other's certificate fingerprint (exchanged during pairing), giving mutual
   authentication. The server and relay only carry ciphertext.
4. **Data plane.** Each forwarded TCP connection is one QUIC stream, so many
   connections and multiple ports multiplex over a single tunnel with no
   head-of-line blocking between them.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for wire details.

## Security notes

- Traffic is end-to-end encrypted; no signaling broker, rendezvous server, or
  TURN relay can read it, and none can MITM it (PAKE authenticates the code).
- The public broker only ever sees ciphertext and a rendezvous topic derived
  from the code (`HKDF(code)`), which is unguessable without the code itself.
  It does learn both peers' IP addresses, as any signaling service would.
- Codes are one-time; broker-mode codes are high-entropy (no server-side
  rate-limiting backs them, so the code alone must resist guessing). Rendezvous
  room codes additionally expire (~10 min), burn on a failed PAKE, and are
  per-IP rate-limited by the server.
- Run `xtunneld` behind TLS (`--tls-cert/--tls-key`, or a reverse proxy) so
  signaling metadata is encrypted in transit.
- `--expose` is an allowlist: the host only ever dials the exact ports you name,
  on `127.0.0.1`.

## Limitations (v1)

- Networks that block UDP entirely have no path (QUIC needs UDP end to end).
- Broker and offline modes have no relay fallback (STUN only) and no
  auto-reconnect — a dropped tunnel needs a fresh code. Use rendezvous mode for
  relay + auto-reconnect.
- pion/ice has no birthday-paradox probing, so a minority of symmetric-NAT
  pairs fall back to the relay (rendezvous mode only).
- The default public broker (ntfy.sh) is a third-party service; override it with
  `--signal-url` or self-host if you need a reliability/privacy guarantee.

## Development

```sh
go test ./...            # unit + integration tests
go vet ./...
./scripts/build-release.sh   # cross-compile all platforms into dist/
```

## License

MIT — see [LICENSE](LICENSE).
