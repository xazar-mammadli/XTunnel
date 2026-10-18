# XTunnel relay on Cloudflare

A signaling relay for XTunnel that runs on the Cloudflare Workers free plan.
It matches two peers by room number and passes their encrypted signaling
messages back and forth. It never carries tunnel traffic, never sees the secret
part of a code, and cannot decrypt anything it relays.

Each room is a Durable Object that uses the WebSocket Hibernation API, so a
waiting peer costs nothing while idle.

## Deploy

You need Node.js and a free Cloudflare account.

```sh
cd relay/cloudflare
npm ci
npx wrangler login
npx wrangler deploy
```

Wrangler prints the URL, for example
`https://xtunnel-relay.<your-subdomain>.workers.dev`. Use it as the server:

```sh
xtunnel share 5432 --server wss://xtunnel-relay.<your-subdomain>.workers.dev
```

or set `XTUNNEL_SERVER` once in your shell profile.

If your account rejects the `ratelimits` binding, delete the `[[ratelimits]]`
block from `wrangler.toml`; the relay then runs without the per-IP limit.

## Limits and abuse protection

The free plan is a hard cap: when the daily quota is used up, requests fail
until midnight UTC and nothing is billed. Clients then report that the relay is
busy.

| Protection | Where |
| --- | --- |
| Per-IP limit: 30 room operations per minute per Cloudflare location | `[[ratelimits]]` in `wrangler.toml` |
| At most two peers per room; a room is single-use | Durable Object |
| 16 messages per peer, 32 KiB each; violators are disconnected | Durable Object |
| Unpaired rooms expire after 10 minutes, paired rooms after 5 | `UNPAIRED_TTL_MS`, `PAIRED_TTL_MS` |
| No TURN credentials are issued | by design |

One pairing costs about two Worker requests and two to three Durable Object
requests, so the free plan handles tens of thousands of pairings a day. For
more control, put the Worker on a custom domain and add a WAF rate limiting
rule in front of it.

## Develop

```sh
npm ci
npm run typecheck
npx wrangler dev --var UNPAIRED_TTL_MS:2000
```

With the dev server running, the Go end-to-end tests exercise the real relay:

```sh
XTUNNEL_TEST_RELAY=ws://127.0.0.1:8787 XTUNNEL_TEST_RELAY_SHORT_TTL=1 \
  go test ./cmd/xtunnel -run Relay
```
