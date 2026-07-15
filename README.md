# xtunnel

Peer-to-peer encrypted TCP port forwarding across NATs. Two machines on
different networks establish a direct, end-to-end-encrypted tunnel — like
WebRTC, but for forwarding ports from a terminal.

- **Direct P2P** via ICE/STUN hole punching; falls back to a relay when hole
  punching fails.
- **End-to-end encrypted** with QUIC/TLS 1.3 and certificate-fingerprint
  pinning. The rendezvous server and relay only ever see ciphertext.
- **Two pairing modes**: a self-hosted rendezvous server with short room codes,
  or fully serverless copy-paste pairing codes.
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

There are two ways to pair the two sides. Both give the same encrypted tunnel;
they differ only in how the two peers first find each other.

### Manual mode (no server)

The side that shares a port runs `offer`; the other runs `answer`. You copy two
short codes between them over any channel (chat, email, a phone call).

```sh
# Machine A — share local port 5432 (e.g. Postgres):
$ xtunnel offer --expose 5432
your pairing code (108 chars) — send it to the other side:
xt1_EQABAgMEBQ...          # <- send this to B

# Machine B — forward local port 15432 to A's port 5432:
$ xtunnel answer xt1_EQABAgMEBQ... -L 15432:5432
your reply code (108 chars) — send it back to the offerer:
xt1_HZk3pR8s...            # <- send this back to A

# Machine A — paste B's reply at the prompt, and the tunnel comes up.
```

Now on machine B, `psql -h 127.0.0.1 -p 15432` reaches A's Postgres.

The pairing codes are only valid for a short window (NAT bindings go stale), so
exchange them promptly. Manual mode has no relay unless you pass
`--turn url,user,pass`.

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
7-zebra-canyon

# Machine B:
$ xtunnel join 7-zebra-canyon --server wss://tunnel.example.com -L 15432:5432
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

1. **Pairing.** In rendezvous mode both peers run a PAKE (SPAKE2 over P-256)
   keyed by the room code, so a malicious or compromised server gets only one
   online guess. In manual mode the copy-paste channel is the trust anchor.
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

- Traffic is end-to-end encrypted; neither the rendezvous server nor the TURN
  relay can read it.
- Room codes are one-time, expire after ~10 minutes, and are burned on a failed
  PAKE attempt; the server rate-limits room creation and joins per IP.
- Run `xtunneld` behind TLS (`--tls-cert/--tls-key`, or a reverse proxy) so
  signaling metadata is encrypted in transit.
- `--expose` is an allowlist: the host only ever dials the exact ports you name,
  on `127.0.0.1`.

## Limitations (v1)

- Networks that block UDP entirely have no path (QUIC needs UDP end to end).
- Manual mode cannot auto-reconnect — a dropped tunnel needs fresh codes.
- pion/ice has no birthday-paradox probing, so a minority of symmetric-NAT
  pairs fall back to the relay.

## Development

```sh
go test ./...            # unit + integration tests
go vet ./...
./scripts/build-release.sh   # cross-compile all platforms into dist/
```

## License

MIT — see [LICENSE](LICENSE).
