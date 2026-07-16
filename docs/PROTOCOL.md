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

- **Offline mode:** inside the pairing blob (the copy-paste channel is the
  trust anchor).
- **Rendezvous and broker modes:** inside the PAKE-encrypted `hello` frame.

## Signaling modes

The PAKE transcript is `xtunnel/1|<mode>|<code>`, where `<mode>` is one of
`rendezvous` or `broker`, so a code from one mode can never be replayed against
the other.

- **rendezvous** — via a self-hosted `xtunneld` mailbox (routing nameplate +
  secret words; server-side one-time rooms, TTL, PAKE burn, rate limiting; TURN
  relay fallback; auto-reconnect).
- **broker** — via a public generic pub/sub broker (ntfy by default), used for
  signaling only. The whole code is a single high-entropy one-time word phrase
  (`NewPairingCode`, ~42 bits). The rendezvous topics are
  `xt-<base32(HKDF(code,"xtunnel/broker/topic"))>-o` (offerer publishes) and
  `-a` (answerer publishes); each side subscribes to the other's. Frames are
  base64 (to stay UTF-8 and under the broker's message-size limit). No relay,
  no auto-reconnect. The broker is untrusted: PAKE bounds it to one online
  guess and it only sees ciphertext + topic + peer IPs.

Both modes reuse the same `SecureChannel` (PAKE + AEAD frames) and the same
connection-round protocol below; only the `Transport` differs.

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
                  {type: "join", room}      // room = nameplate only
                  {type: "msg",  body}
server → client:  {type: "created", room, turn?}   // room = nameplate
                  {type: "joined", turn?}
                  {type: "peer"}            // host: a joiner arrived
                  {type: "msg", body}       // relayed opaque payload
                  {type: "peer-left"}
                  {type: "error", error}
```

The server relays `body` blindly between the two peers in a room. It never sees
inside `body`. `turn` carries ephemeral relay credentials when the server runs
an embedded TURN relay.

**Code split (server cannot MITM).** The full pairing code is
`nameplate-word-word-word`, e.g. `42731-apple-river-cedar`. The **nameplate**
(`42731`) is assigned by the server and used only for routing — it is the
`room` in join/create envelopes. The **secret words** are generated
client-side with local entropy (~21 bits) and are the PAKE password material;
they never reach the server. Because the server never learns the full code, it
cannot derive the SPAKE2 session key, so it cannot decrypt signaling or splice
a man-in-the-middle session — even though it relays the ciphertext. Nameplates
are one-time, ~10 minute unpaired TTL, and the room is burned on a failed PAKE.

### PAKE and encrypted frames

Both peers run SPAKE2 over P-256 (`schollz/pake` v3, explicitly the P-256
curve) keyed by the transcript `xtunnel/1|rendezvous|<full-code>` — the full
code including the client-generated secret words, which the server never sees.
The two PAKE messages are exchanged through the mailbox. The resulting shared
secret is expanded with HKDF into two ChaCha20-Poly1305 keys (one per
direction):

```
hostKey = HKDF-SHA256(K, info="xtunnel/sig/host->join")
joinKey = HKDF-SHA256(K, info="xtunnel/sig/join->host")
```

Every subsequent `msg` body is an AEAD frame:

```
[8B counter, big endian] || AEAD_seal(key, nonce=counter, plaintext, aad=counter)
```

The counter is the nonce and is checked for strict monotonicity (replay
protection). A background read pump owns all mailbox reads for the channel's
lifetime, decrypting frames onto a buffered queue — this lets keepalive pings
have their pongs processed while no round is receiving, and lets a reconnect
round drain stale frames. The plaintext is `{"t": type, "d": payload}`. A
decryption failure means the two sides derived different keys — i.e. a wrong or
guessed code — and pairing aborts. This bounds a malicious server to one online
guess per code.

### Connection rounds

Signaling frame types: `hello` (per round). Candidates are bundled inside the
`hello` frame (non-trickle), so each round is a clean two-message exchange:

```
hello = {fp, ufrag, pwd, cands: [ICE candidate strings], rid, reply}
```

Ordering per round: the **joiner opens** with a fresh random round id `rid`
(`reply=false`); the **host echoes** that `rid` (`reply=true`) in its response.
Each side rejects a `hello` that does not belong to the current round (wrong
`rid`, or a stale opener), and both drain buffered frames at round start, so a
frame left over from an aborted round can never desync the loop. Both then add
the peer's candidates, run ICE (host dials, joiner accepts), and perform the
QUIC handshake. On reconnect the same secure channel is reused for a new round —
no new PAKE, no new code. The reconnect round timeout (90s) exceeds the QUIC
idle timeout (60s) so a peer always has time to notice a drop and answer before
the other re-sends.

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
