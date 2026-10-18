package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/peer"
	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

const (
	reconnectTimeout = 90 * time.Second
	reconnectDelay   = 2 * time.Second
	keepaliveEvery   = 25 * time.Second
	gatherTimeout    = 3 * time.Second
)

func shareSignaled(ctx context.Context, o *options, ports []uint16, out *console) error {
	server, err := o.serverURL()
	if err != nil {
		return err
	}
	mb, nameplate, err := sig.Create(ctx, server)
	if err != nil {
		return err
	}
	defer mb.Close()
	go mb.Keepalive(ctx, keepaliveEvery)

	secret, err := sig.NewSecret()
	if err != nil {
		return err
	}
	code := nameplate + "-" + secret
	out.showCode(code)
	out.say("Waiting for the other side (up to %s)...", humanDuration(o.timeout))

	wctx, cancel := context.WithTimeout(ctx, o.timeout)
	err = mb.WaitPeer(wctx)
	cancel()
	switch {
	case ctx.Err() != nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return errWaitTimeout
	case err != nil:
		return err
	}
	out.say("The other side is here, connecting...")

	return runSignaled(ctx, mb, code, true, o, out, func(ctx context.Context, s *peer.Session) error {
		return serveHost(ctx, s, ports, out)
	})
}

func connectSignaled(ctx context.Context, o *options, code string, forwards []tunnel.Forward, out *console) error {
	server, err := o.serverURL()
	if err != nil {
		return err
	}
	out.say("Connecting...")
	mb, err := sig.Join(ctx, server, sig.Nameplate(code))
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer mb.Close()
	go mb.Keepalive(ctx, keepaliveEvery)

	return runSignaled(ctx, mb, code, false, o, out, func(ctx context.Context, s *peer.Session) error {
		return serveJoiner(ctx, s, forwards, out)
	})
}

func runSignaled(
	ctx context.Context,
	mb *sig.Mailbox,
	code string,
	isHost bool,
	o *options,
	out *console,
	serve func(context.Context, *peer.Session) error,
) error {
	sc, err := sig.Secure(ctx, mb, code, isHost)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	turns := append([]icewrap.TURNServer(nil), o.turn...)
	for _, t := range mb.TURNServers() {
		turns = append(turns, icewrap.TURNServer{URL: t.URL, Username: t.Username, Password: t.Password})
	}
	l := &loop{sc: sc, o: o, turns: turns, isHost: isHost, out: out}
	retry := mb.Reconnect() && !o.noRetry

	for first := true; ; first = false {
		timeout := reconnectTimeout
		if first {
			timeout = o.timeout
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		sess, ep, err := l.round(rctx)
		cancel()

		if ctx.Err() != nil {
			if err == nil {
				_ = sess.Close()
				_ = ep.Close()
			}
			return nil
		}
		if err != nil {
			if first || !retry || sc.Err() != nil {
				return err
			}
			out.say("Reconnect failed (%s), retrying...", friendly(err))
			if !sleepCtx(ctx, reconnectDelay) {
				return nil
			}
			continue
		}

		if !retry {
			_ = sc.Close()
		}
		if !first {
			out.say("Reconnected.")
		}
		out.connected(ep)

		err = finish(serve(ctx, sess), out)
		_ = ep.Close()
		if ctx.Err() != nil || err == nil {
			return nil
		}
		if !retry {
			return err
		}
		out.say("Connection lost, reconnecting...")
		if !sleepCtx(ctx, reconnectDelay) {
			return nil
		}
	}
}

type loop struct {
	sc     *sig.SecureChannel
	o      *options
	turns  []icewrap.TURNServer
	isHost bool
	out    *console
}

func (l *loop) round(ctx context.Context) (*peer.Session, *icewrap.Endpoint, error) {
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return nil, nil, err
	}
	ep, err := icewrap.New(icewrap.Config{
		STUNServers:     l.o.stunServers(),
		TURNServers:     l.turns,
		IncludeLoopback: l.o.includeLoopback,
		RelayOnly:       l.o.forceRelay,
	})
	if err != nil {
		return nil, nil, err
	}
	l.out.watchICE(ep)

	ok := false
	defer func() {
		if !ok {
			_ = ep.Close()
		}
	}()

	ufrag, pwd, err := ep.Credentials()
	if err != nil {
		return nil, nil, err
	}

	gctx, gcancel := context.WithTimeout(ctx, gatherTimeout)
	cands, err := ep.GatherAll(gctx)
	gcancel()
	if err != nil {
		return nil, nil, fmt.Errorf("gather candidates: %w", err)
	}
	marshaled := make([]string, 0, len(cands))
	for _, c := range cands {
		marshaled = append(marshaled, c.Marshal())
	}
	if len(marshaled) == 0 {
		return nil, nil, errors.New("no usable network addresses (offline?)")
	}

	local := &sig.Hello{FP: hex.EncodeToString(fp[:]), Ufrag: ufrag, Pwd: pwd, Cands: marshaled}

	var remote *sig.Hello
	if l.isHost {
		if remote, err = l.recvOpener(ctx); err != nil {
			return nil, nil, err
		}
		local.Rid, local.Reply = remote.Rid, true
		if err = l.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
	} else {
		rid, rerr := randRid()
		if rerr != nil {
			return nil, nil, rerr
		}
		l.sc.Drain()
		local.Rid = rid
		if err = l.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
		if remote, err = l.recvReply(ctx, rid); err != nil {
			return nil, nil, err
		}
	}

	fpBytes, err := hex.DecodeString(remote.FP)
	if err != nil || len(fpBytes) != len(xcrypto.Fingerprint{}) {
		return nil, nil, errors.New("malformed peer fingerprint")
	}
	var expected xcrypto.Fingerprint
	copy(expected[:], fpBytes)

	for _, raw := range remote.Cands {
		if err := ep.AddRemoteCandidate(raw); err != nil {
			l.out.debugf("skipping remote candidate: %v", err)
		}
	}

	sess, err := l.establish(ctx, ep, remote, cert, expected)
	if err != nil {
		return nil, nil, err
	}
	ok = true
	return sess, ep, nil
}

func (l *loop) establish(ctx context.Context, ep *icewrap.Endpoint, remote *sig.Hello, cert tls.Certificate, expected xcrypto.Fingerprint) (*peer.Session, error) {
	dial := ep.Accept
	if l.isHost {
		dial = ep.Dial
	}
	ic, err := dial(ctx, remote.Ufrag, remote.Pwd)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoPath, err)
	}
	sess, err := peer.EstablishQUIC(ctx, ic, l.isHost, cert, expected)
	if err != nil {
		return nil, fmt.Errorf("secure handshake failed: %w", err)
	}
	return sess, nil
}

func decodeHello(raw json.RawMessage) (*sig.Hello, error) {
	var h sig.Hello
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("malformed hello: %w", err)
	}
	return &h, nil
}

func (l *loop) recvOpener(ctx context.Context) (*sig.Hello, error) {
	var latest *sig.Hello
	for latest == nil {
		t, raw, err := l.sc.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if t != sig.MsgHello {
			continue
		}
		h, err := decodeHello(raw)
		if err != nil {
			return nil, err
		}
		if !h.Reply {
			latest = h
		}
	}
	for {
		t, raw, ok := l.sc.TryRecv()
		if !ok {
			return latest, nil
		}
		if t != sig.MsgHello {
			continue
		}
		if h, err := decodeHello(raw); err == nil && !h.Reply {
			latest = h
		}
	}
}

func (l *loop) recvReply(ctx context.Context, rid string) (*sig.Hello, error) {
	for {
		t, raw, err := l.sc.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if t != sig.MsgHello {
			continue
		}
		h, err := decodeHello(raw)
		if err != nil {
			return nil, err
		}
		if h.Reply && h.Rid == rid {
			return h, nil
		}
	}
}

func randRid() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
