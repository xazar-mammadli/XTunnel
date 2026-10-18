package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/blob"
	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/peer"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

const staleAfter = 60 * time.Second

func shareOffline(ctx context.Context, o *options, ports []uint16, out *console) error {
	seed, err := blob.NewSeed()
	if err != nil {
		return err
	}
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return err
	}
	ep, packed, err := offlineEndpoint(ctx, seed, o, out)
	if err != nil {
		return err
	}
	defer ep.Close()

	code := (&blob.Blob{Seed: seed, Fingerprint: fp, Candidates: packed}).Encode()
	out.showBlob("Send this code to the other side:", code)
	out.say("Then paste their reply code here and press Enter:")

	reply, err := readBlobFromStdin(ctx, true, out)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	stop := staleWarning(ctx, out)
	defer stop()
	if err := addRemoteFromBlob(ep, reply); err != nil {
		return err
	}
	rufrag, rpwd, err := blob.DeriveICECredentials(reply.Seed)
	if err != nil {
		return err
	}

	pctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	out.say("Connecting...")
	ic, err := ep.Dial(pctx, rufrag, rpwd)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%w: %v", errNoPath, err)
	}
	sess, err := peer.EstablishQUIC(pctx, ic, true, cert, reply.Fingerprint)
	if err != nil {
		return fmt.Errorf("secure handshake failed: %w", err)
	}
	out.connected(ep)
	return finish(serveHost(ctx, sess, ports, out), out)
}

func connectOffline(ctx context.Context, o *options, code string, forwards []tunnel.Forward, out *console) error {
	offer, err := blob.Decode(code)
	if err != nil {
		return usageError(fmt.Sprintf("invalid offline code: %v", err))
	}
	if offer.IsAnswer {
		return usageError("that is a reply code; use the code printed by 'xtunnel share --offline'")
	}

	seed, err := blob.NewSeed()
	if err != nil {
		return err
	}
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return err
	}
	ep, packed, err := offlineEndpoint(ctx, seed, o, out)
	if err != nil {
		return err
	}
	defer ep.Close()

	reply := (&blob.Blob{IsAnswer: true, Seed: seed, Fingerprint: fp, Candidates: packed}).Encode()
	out.showBlob("Send this reply code back to the other side:", reply)

	stop := staleWarning(ctx, out)
	defer stop()
	if err := addRemoteFromBlob(ep, offer); err != nil {
		return err
	}
	rufrag, rpwd, err := blob.DeriveICECredentials(offer.Seed)
	if err != nil {
		return err
	}

	pctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	out.say("Connecting (waiting for the other side to paste the reply)...")
	ic, err := ep.Accept(pctx, rufrag, rpwd)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%w: %v", errNoPath, err)
	}
	sess, err := peer.EstablishQUIC(pctx, ic, false, cert, offer.Fingerprint)
	if err != nil {
		return fmt.Errorf("secure handshake failed: %w", err)
	}
	out.connected(ep)
	return finish(serveJoiner(ctx, sess, forwards, out), out)
}

func offlineEndpoint(ctx context.Context, seed [16]byte, o *options, out *console) (*icewrap.Endpoint, []blob.Candidate, error) {
	ufrag, pwd, err := blob.DeriveICECredentials(seed)
	if err != nil {
		return nil, nil, err
	}
	ep, err := icewrap.New(icewrap.Config{
		STUNServers:     o.stunServers(),
		TURNServers:     o.turn,
		LocalUfrag:      ufrag,
		LocalPwd:        pwd,
		IncludeLoopback: o.includeLoopback,
	})
	if err != nil {
		return nil, nil, err
	}
	out.watchICE(ep)

	gctx, cancel := context.WithTimeout(ctx, gatherTimeout)
	defer cancel()
	cands, err := ep.GatherAll(gctx)
	if err != nil {
		_ = ep.Close()
		return nil, nil, fmt.Errorf("gather candidates: %w", err)
	}
	packed := blob.PackCandidates(cands)
	if len(packed) == 0 {
		_ = ep.Close()
		return nil, nil, errors.New("no usable network addresses (offline?)")
	}
	return ep, packed, nil
}

func addRemoteFromBlob(ep *icewrap.Endpoint, b *blob.Blob) error {
	cands, err := blob.ToICECandidates(b.Candidates)
	if err != nil {
		return err
	}
	for _, c := range cands {
		if err := ep.AddRemoteCandidateObj(c); err != nil {
			return fmt.Errorf("add remote candidate: %w", err)
		}
	}
	return nil
}

func staleWarning(ctx context.Context, out *console) (stop func()) {
	t := time.AfterFunc(staleAfter, func() {
		if ctx.Err() == nil {
			out.say("Still connecting. If it fails, create new codes on both sides and exchange them faster.")
		}
	})
	return func() { t.Stop() }
}

func readBlobFromStdin(ctx context.Context, wantAnswer bool, out *console) (*blob.Blob, error) {
	type result struct {
		b   *blob.Blob
		err error
	}
	ch := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			b, err := blob.Decode(line)
			if err != nil {
				out.say("That code is invalid (%v). Paste the full xt1_... code:", err)
				continue
			}
			if b.IsAnswer != wantAnswer {
				out.say("That is your own code. Paste the one from the other side:")
				continue
			}
			ch <- result{b, nil}
			return
		}
		err := sc.Err()
		if err == nil {
			err = errors.New("input closed before a valid code was entered")
		}
		ch <- result{nil, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
