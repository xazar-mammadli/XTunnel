# xtunnel protocol

This document describes the xtunnel v1 wire protocol. The application protocol
negotiated over QUIC ALPN is `xtunnel/1`.

## Identity and authentication

Each peer generates an ephemeral self-signed ECDSA P-256 certificate per
session. Authentication is by pinning the SHA-256 fingerprint of the peer's
leaf certificate; the certificate chain is never trusted (QUIC runs with
`InsecureSkipVerify` plus a `VerifyPeerCertificate` that compares the leaf
digest to the expected fingerprint). Both directions are pinned, so the
handshake is mutually authenticated.

Fingerprints are delivered out of band:

- **Manual mode:** inside the pairing blob (the copy-paste channel is the
  trust anchor).
- **Rendezvous mode:** inside the PAKE-encrypted `hello` frame.

## Roles

Fixed for the whole session, decided at pairing time:

| Party | ICE role | QUIC role |
| --- | --- | --- |
| offer creator / room host | controlling | client (dials) |
| answerer / room joiner | controlled | server (listens) |

## Manual pairing blob

Printable form: `xt1_` + base64url(raw), no padding. Raw layout:

```
[1B  version<<4 | flags]      flags bit0: 1 = answer blob
[16B seed]                    ICE ufrag/pwd derived from this
[32B cert SHA-256 fingerprint]
[1B  candidate count]         (<= 8)
repeated candidate:
  [1B  flags]                 bit0: 1 = IPv6
  [4B or 16B IP]
  [2B port, big endian]
```

ICE credentials are not transmitted. Both sides derive them from the seed:

```
ufrag = base64std( HKDF-SHA256(seed, info="xtunnel/ice-ufrag", 12 bytes) )
pwd   = base64std( HKDF-SHA256(seed, info="xtunnel/ice-pwd",   18 bytes) )
```

Typical blobs are 90–140 characters.

## Rendezvous signaling

### Mailbox envelope (peer ↔ xtunneld, JSON over WebSocket)

```
client → server:  {type: "create"}
                  {type: "join", room}
                  {type: "msg",  body}
server → client:  {type: "created", room, turn?}
                  {type: "joined", turn?}
                  {type: "peer"}            // host: a joiner arrived
                  {type: "msg", body}       // relayed opaque payload
                  {type: "peer-left"}
                  {type: "error", error}
```

The server relays `body` blindly between the two peers in a room. It never sees
inside `body`. Room codes are `N-word-word` (~20 bits), one-time, ~10 minute
TTL, burned on a failed PAKE. `turn` carries ephemeral relay credentials when
the server runs an embedded TURN relay.

### PAKE and encrypted frames

Both peers run SPAKE2 over P-256 (`schollz/pake` v3, explicitly the P-256
curve) keyed by the transcript `xtunnel/1|rendezvous|<code>`, exchanging the two
PAKE messages through the mailbox. The resulting shared secret is expanded with
HKDF into two ChaCha20-Poly1305 keys (one per direction):

```
hostKey = HKDF-SHA256(K, info="xtunnel/sig/host->join")
joinKey = HKDF-SHA256(K, info="xtunnel/sig/join->host")
```

Every subsequent `msg` body is an AEAD frame:

```
[8B counter, big endian] || AEAD_seal(key, nonce=counter, plaintext, aad=counter)
```

The counter is the nonce and is checked for strict monotonicity (replay
protection). The plaintext is `{"t": type, "d": payload}`. A decryption failure
on the first frame means the two sides derived different keys — i.e. a wrong or
guessed room code — and pairing aborts. This bounds a malicious server to one
online guess per code.

### Connection rounds

Signaling frame types: `hello` (per round). Candidates are bundled inside the
`hello` frame (non-trickle), so each round is a clean two-message exchange:

```
hello = {fp, ufrag, pwd, cands: [ICE candidate strings]}
```

Ordering per round: the **joiner sends its `hello` first**, the host responds.
Both then add the peer's candidates, run ICE (host dials, joiner accepts), and
perform the QUIC handshake. On reconnect the same secure channel is reused for a
new round — no new PAKE, no new room code.

## Data plane (over QUIC)

- One QUIC connection per peer pair.
- The **host** opens one control stream first and sends the port registry:

  ```
  [1B  type=0x01 registry][2B count][2B port]...   (host → joiner)
  ```

- The **joiner** opens one bidirectional stream per forwarded TCP connection:

  ```
  [1B protocol version][2B target port]            (joiner → host)
  ```

  The host replies with one status byte (`0x00` OK, `0x01` port refused,
  `0x02` local dial failed), then raw bytes flow both ways.

- TCP half-close maps to QUIC stream FIN; abnormal teardown maps to
  `CancelRead`/`CancelWrite`. Multiple ports and many connections multiplex
  over the single connection with per-stream flow control.

## Relay fallback

The embedded TURN server (pion/turn) issues time-windowed credentials
(RFC 8489 long-term style): username = expiry unix timestamp, password =
base64(HMAC-SHA1(username, shared secret)). Peers add the relay as an ICE
server; if hole punching fails, ICE nominates a relay candidate pair. QUIC/TLS
terminates only at the peers, so the relay forwards ciphertext. `InitialPacketSize`
is capped at 1150 bytes and PMTUD is disabled to stay within TURN framing
overhead.
