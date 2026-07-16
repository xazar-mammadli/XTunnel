package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xazar/xtunnel/internal/blob"
	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/peer"
	sig "github.com/xazar/xtunnel/internal/signal"
	"github.com/xazar/xtunnel/internal/signal/broker"
	"github.com/xazar/xtunnel/internal/xcrypto"
)

// manualFlags are the options shared by offer and answer.
type manualFlags struct {
	stun            stringList
	turn            turnList
	gatherTimeout   time.Duration
	pairTimeout     time.Duration
	includeLoopback bool
	offline         bool
	signalURL       string
}

func (m *manualFlags) register(fs *flag.FlagSet) {
	fs.Var(&m.stun, "stun", "STUN server URI (repeatable)")
	fs.Var(&m.turn, "turn", "TURN relay as url,username,password (repeatable)")
	fs.DurationVar(&m.gatherTimeout, "gather-timeout", 3*time.Second, "candidate gathering deadline")
	fs.DurationVar(&m.pairTimeout, "pair-timeout", 3*time.Minute, "window for completing the pairing")
	fs.BoolVar(&m.includeLoopback, "include-loopback", false, "gather loopback candidates (same-machine testing)")
	fs.BoolVar(&m.offline, "offline", false, "use offline two-way copy-paste blobs instead of a public signaling broker")
	fs.StringVar(&m.signalURL, "signal-url", broker.DefaultURL, "public pub/sub broker used only for signaling (not the tunnel)")
}

func (m *manualFlags) stunServers() []string {
	if len(m.stun) > 0 {
		return m.stun
	}
	return defaultSTUN
}

// manualEndpoint builds an ICE endpoint whose credentials are derived from
// the local blob seed, and gathers its candidates.
func manualEndpoint(ctx context.Context, seed [16]byte, m *manualFlags) (*icewrap.Endpoint, []blob.Candidate, error) {
	ufrag, pwd, err := blob.DeriveICECredentials(seed)
	if err != nil {
		return nil, nil, err
	}
	ep, err := icewrap.New(icewrap.Config{
		STUNServers:     m.stunServers(),
		TURNServers:     m.turn,
		LocalUfrag:      ufrag,
		LocalPwd:        pwd,
		IncludeLoopback: m.includeLoopback,
	})
	if err != nil {
		return nil, nil, err
	}
	logICEStates(ep)

	gctx, cancel := context.WithTimeout(ctx, m.gatherTimeout)
	defer cancel()
	cands, err := ep.GatherAll(gctx)
	if err != nil {
		_ = ep.Close()
		return nil, nil, fmt.Errorf("gather candidates: %w", err)
	}
	packed := blob.PackCandidates(cands)
	if len(packed) == 0 {
		_ = ep.Close()
		return nil, nil, errors.New("no usable candidates gathered (network down?)")
	}
	return ep, packed, nil
}

// addRemoteFromBlob installs the remote peer's candidates from its blob.
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

// staleWarning logs a reminder if pairing is still pending after a minute.
func staleWarning(ctx context.Context) (stop func()) {
	t := time.AfterFunc(60*time.Second, func() {
		if ctx.Err() == nil {
			log.Printf("warning: over 60s elapsed — NAT bindings may be getting stale; if the connection fails, regenerate codes on BOTH sides and exchange faster")
		}
	})
	return func() { t.Stop() }
}

func runOffer(args []string) error {
	fs := flag.NewFlagSet("offer", flag.ExitOnError)
	var expose portList
	var mf manualFlags
	fs.Var(&expose, "expose", "local TCP port to share (repeatable, required)")
	mf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(expose) == 0 {
		return errors.New("at least one --expose <port> is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if !mf.offline {
		return runOfferBroker(ctx, expose, &mf)
	}
	return runOfferOffline(ctx, expose, &mf)
}

// runOfferBroker pairs via a public signaling broker with a single short code.
func runOfferBroker(ctx context.Context, expose portList, mf *manualFlags) error {
	code, err := sig.NewPairingCode()
	if err != nil {
		return err
	}
	log.Printf("pairing code — run this on the other machine:")
	fmt.Printf("\n    xtunnel answer %s -L <localport>:%d\n\n", code, expose[0])
	log.Printf("connecting via %s (signaling only; the tunnel stays peer-to-peer)...", mf.signalURL)

	sess, ep, err := brokerPair(ctx, code, true, mf)
	if err != nil {
		return err
	}
	defer ep.Close()
	printPath(ep)
	return serveAsHost(ctx, sess, expose)
}

func runOfferOffline(ctx context.Context, expose portList, mf *manualFlags) error {
	seed, err := blob.NewSeed()
	if err != nil {
		return err
	}
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return err
	}
	ep, packed, err := manualEndpoint(ctx, seed, mf)
	if err != nil {
		return err
	}
	defer ep.Close()

	code := (&blob.Blob{Seed: seed, Fingerprint: fp, Candidates: packed}).Encode()
	log.Printf("your pairing code (%d chars) — send it to the other side:", len(code))
	fmt.Println(code)
	log.Printf("waiting for the reply code (paste it here and press Enter)...")

	ans, err := readBlobFromStdin(ctx, true)
	if err != nil {
		return err
	}

	stop := staleWarning(ctx)
	defer stop()

	if err := addRemoteFromBlob(ep, ans); err != nil {
		return err
	}
	rufrag, rpwd, err := blob.DeriveICECredentials(ans.Seed)
	if err != nil {
		return err
	}

	pctx, pcancel := context.WithTimeout(ctx, mf.pairTimeout)
	defer pcancel()
	log.Printf("connecting...")
	iceConn, err := ep.Dial(pctx, rufrag, rpwd)
	if err != nil {
		return fmt.Errorf("ICE failed (regenerate codes on both sides and retry): %w", err)
	}
	printPath(ep)

	sess, err := peer.EstablishQUIC(pctx, iceConn, true, cert, ans.Fingerprint)
	if err != nil {
		return fmt.Errorf("QUIC handshake: %w", err)
	}
	return serveAsHost(ctx, sess, expose)
}

func runAnswer(args []string) error {
	// Accept the code as the first positional argument, before flags.
	var code string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		code, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("answer", flag.ExitOnError)
	var forwards forwardList
	var mf manualFlags
	fs.Var(&forwards, "L", "forward spec [bind:]local:remote or port (repeatable, required)")
	mf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The code may sit between flags (e.g. `answer --offline <code> -L ...`);
	// Go's flag parser stops at the first positional, so take it as the code
	// and re-parse the flags that follow it.
	if code == "" && fs.NArg() > 0 {
		code = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return err
		}
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("usage: xtunnel answer <pairing-code> -L <local:remote>")
	}
	if len(forwards) == 0 {
		return errors.New("at least one -L <local:remote> is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Dispatch by code shape: an "xt1_" blob is offline copy-paste; a word-only
	// code is a broker-mode pairing code.
	if !strings.HasPrefix(code, blob.Prefix) && sig.ValidPairingCode(code) {
		return runAnswerBroker(ctx, code, forwards, &mf)
	}
	return runAnswerOffline(ctx, code, forwards, &mf)
}

// runAnswerBroker pairs via a public signaling broker using a shared code.
func runAnswerBroker(ctx context.Context, code string, forwards forwardList, mf *manualFlags) error {
	log.Printf("connecting via %s (signaling only; the tunnel stays peer-to-peer)...", mf.signalURL)
	sess, ep, err := brokerPair(ctx, code, false, mf)
	if err != nil {
		return err
	}
	defer ep.Close()
	printPath(ep)
	return serveAsJoiner(ctx, sess, forwards)
}

func runAnswerOffline(ctx context.Context, code string, forwards forwardList, mf *manualFlags) error {
	off, err := blob.Decode(code)
	if err != nil {
		return err
	}
	if off.IsAnswer {
		return errors.New("that is a reply code; pass the OFFER code to 'xtunnel answer'")
	}

	seed, err := blob.NewSeed()
	if err != nil {
		return err
	}
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return err
	}
	ep, packed, err := manualEndpoint(ctx, seed, mf)
	if err != nil {
		return err
	}
	defer ep.Close()

	reply := (&blob.Blob{IsAnswer: true, Seed: seed, Fingerprint: fp, Candidates: packed}).Encode()
	log.Printf("your reply code (%d chars) — send it back to the offerer:", len(reply))
	fmt.Println(reply)

	stop := staleWarning(ctx)
	defer stop()

	if err := addRemoteFromBlob(ep, off); err != nil {
		return err
	}
	rufrag, rpwd, err := blob.DeriveICECredentials(off.Seed)
	if err != nil {
		return err
	}

	pctx, pcancel := context.WithTimeout(ctx, mf.pairTimeout)
	defer pcancel()
	log.Printf("connecting (waiting for the offerer to paste your reply)...")
	iceConn, err := ep.Accept(pctx, rufrag, rpwd)
	if err != nil {
		return fmt.Errorf("ICE failed (regenerate codes on both sides and retry): %w", err)
	}
	printPath(ep)

	sess, err := peer.EstablishQUIC(pctx, iceConn, false, cert, off.Fingerprint)
	if err != nil {
		return fmt.Errorf("QUIC handshake: %w", err)
	}
	return serveAsJoiner(ctx, sess, forwards)
}

// brokerPair runs the broker-mode pairing: PAKE over the public broker, then
// one connection round (candidate exchange + ICE + QUIC). No relay and no
// auto-reconnect — a dropped tunnel needs a fresh code. isHost is the offerer.
func brokerPair(ctx context.Context, code string, isHost bool, mf *manualFlags) (*peer.Session, *icewrap.Endpoint, error) {
	tr, err := broker.Dial(ctx, mf.signalURL, code, isHost)
	if err != nil {
		return nil, nil, err
	}

	pctx, pcancel := context.WithTimeout(ctx, mf.pairTimeout)
	defer pcancel()

	sc, err := sig.Secure(pctx, tr, code, isHost, sig.ModeBroker)
	if err != nil {
		_ = tr.Close()
		return nil, nil, fmt.Errorf("pairing handshake failed (wrong code, or the other side not ready): %w", err)
	}

	rf := &rendezvousFlags{stun: mf.stun, includeLoopback: mf.includeLoopback}
	rl := &rendezvousLoop{sc: sc, rf: rf, turns: nil, isHost: isHost}
	sess, ep, err := rl.round(pctx)
	if err != nil {
		_ = sc.Close()
		return nil, nil, err
	}
	// Signaling is complete; the tunnel is direct peer-to-peer now.
	_ = sc.Close()
	return sess, ep, nil
}

// readBlobFromStdin reads one pairing code line from stdin, honoring ctx.
func readBlobFromStdin(ctx context.Context, wantAnswer bool) (*blob.Blob, error) {
	type res struct {
		b   *blob.Blob
		err error
	}
	ch := make(chan res, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			b, err := blob.Decode(line)
			if err != nil {
				log.Printf("invalid code (%v) — paste the full xt1_... string:", err)
				continue
			}
			if b.IsAnswer != wantAnswer {
				log.Printf("that looks like your own code — paste the one from the OTHER side:")
				continue
			}
			ch <- res{b, nil}
			return
		}
		err := sc.Err()
		if err == nil {
			err = errors.New("stdin closed before a valid code was entered")
		}
		ch <- res{nil, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
