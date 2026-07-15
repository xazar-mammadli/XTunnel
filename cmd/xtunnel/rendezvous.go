package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/peer"
	sig "github.com/xazar/xtunnel/internal/signal"
	"github.com/xazar/xtunnel/internal/xcrypto"
)

// rendezvousFlags are the options shared by host and join.
type rendezvousFlags struct {
	server          string
	stun            stringList
	turn            turnList
	pairTimeout     time.Duration
	includeLoopback bool
	forceRelay      bool
	retry           bool
}

func (r *rendezvousFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.server, "server", os.Getenv("XTUNNEL_SERVER"), "xtunneld URL, e.g. wss://tunnel.example.com (or $XTUNNEL_SERVER)")
	fs.Var(&r.stun, "stun", "STUN server URI (repeatable)")
	fs.Var(&r.turn, "turn", "extra TURN relay as url,username,password (repeatable)")
	fs.DurationVar(&r.pairTimeout, "pair-timeout", 10*time.Minute, "how long to wait for the peer")
	fs.BoolVar(&r.includeLoopback, "include-loopback", false, "gather loopback candidates (same-machine testing)")
	fs.BoolVar(&r.forceRelay, "force-relay", false, "use only relay candidates (testing the TURN fallback path)")
	fs.BoolVar(&r.retry, "retry", true, "keep the rendezvous connection open and auto-reconnect if the tunnel drops")
}

func (r *rendezvousFlags) stunServers() []string {
	if len(r.stun) > 0 {
		return r.stun
	}
	return defaultSTUN
}

// reconnect pacing for non-interactive rounds after the initial pairing.
const (
	reconnectTimeout = 45 * time.Second
	reconnectDelay   = 2 * time.Second
	keepaliveEvery   = 25 * time.Second
)

func runHost(args []string) error {
	fs := flag.NewFlagSet("host", flag.ExitOnError)
	var expose portList
	var rf rendezvousFlags
	fs.Var(&expose, "expose", "local TCP port to share (repeatable, required)")
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if rf.server == "" {
		return errors.New("--server (or $XTUNNEL_SERVER) is required")
	}
	if len(expose) == 0 {
		return errors.New("at least one --expose <port> is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mb, err := sig.DialMailbox(ctx, rf.server)
	if err != nil {
		return err
	}
	defer mb.Close()

	code, err := mb.CreateRoom(ctx)
	if err != nil {
		return err
	}
	log.Printf("room code — give it to the joining side:")
	fmt.Println(code)
	log.Printf("waiting for peer (up to %s)...", rf.pairTimeout)

	wctx, wcancel := context.WithTimeout(ctx, rf.pairTimeout)
	err = mb.WaitPeer(wctx)
	wcancel()
	if err != nil {
		return fmt.Errorf("waiting for peer: %w", err)
	}
	log.Printf("peer joined, authenticating...")

	serve := func(ctx context.Context, s *peer.Session) error {
		return serveAsHost(ctx, s, expose)
	}
	return runRendezvousLoop(ctx, mb, code, true, &rf, serve)
}

func runJoin(args []string) error {
	// Accept the room code as the first positional argument, before flags.
	var code string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		code, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("join", flag.ExitOnError)
	var forwards forwardList
	var rf rendezvousFlags
	fs.Var(&forwards, "L", "forward spec [bind:]local:remote or port (repeatable, required)")
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if code == "" && fs.NArg() > 0 {
		code = fs.Arg(0)
	}
	if code == "" {
		return errors.New("usage: xtunnel join <room-code> --server <url> -L <local:remote>")
	}
	if rf.server == "" {
		return errors.New("--server (or $XTUNNEL_SERVER) is required")
	}
	if len(forwards) == 0 {
		return errors.New("at least one -L <local:remote> is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mb, err := sig.DialMailbox(ctx, rf.server)
	if err != nil {
		return err
	}
	defer mb.Close()

	if err := mb.JoinRoom(ctx, strings.TrimSpace(code)); err != nil {
		return err
	}
	log.Printf("joined room, authenticating...")

	serve := func(ctx context.Context, s *peer.Session) error {
		return serveAsJoiner(ctx, s, forwards)
	}
	return runRendezvousLoop(ctx, mb, code, false, &rf, serve)
}

// rendezvousLoop holds the state reused across (re)connection rounds.
type rendezvousLoop struct {
	sc     *sig.SecureChannel
	rf     *rendezvousFlags
	turns  []icewrap.TURNServer
	isHost bool
}

// runRendezvousLoop performs the PAKE once, then repeatedly establishes the
// tunnel and serves it. If retry is enabled it reconnects over the same
// rendezvous mailbox whenever the QUIC connection drops, until the user
// interrupts.
func runRendezvousLoop(
	ctx context.Context,
	mb *sig.Mailbox,
	code string,
	isHost bool,
	rf *rendezvousFlags,
	serve func(context.Context, *peer.Session) error,
) error {
	sc, err := sig.Secure(ctx, mb, code, isHost)
	if err != nil {
		return err
	}

	// Keep the mailbox alive for the tunnel's lifetime so reconnect signaling
	// keeps working across long idle periods.
	go mb.Keepalive(ctx, keepaliveEvery)

	turns := append([]icewrap.TURNServer(nil), rf.turn...)
	for _, t := range mb.TURNServers() {
		turns = append(turns, icewrap.TURNServer{URL: t.URL, Username: t.Username, Password: t.Password})
	}
	if len(turns) > len(rf.turn) {
		log.Printf("relay fallback available via server-issued TURN credentials")
	}

	rl := &rendezvousLoop{sc: sc, rf: rf, turns: turns, isHost: isHost}

	first := true
	for {
		roundTimeout := reconnectTimeout
		if first {
			roundTimeout = rf.pairTimeout
		}
		rctx, rcancel := context.WithTimeout(ctx, roundTimeout)
		sess, ep, err := rl.round(rctx)
		rcancel()

		if err != nil {
			if ctx.Err() != nil {
				return nil // user interrupted
			}
			if first || !rf.retry {
				return err
			}
			log.Printf("reconnect failed: %v — retrying in %s", err, reconnectDelay)
			if !sleepCtx(ctx, reconnectDelay) {
				return nil
			}
			continue
		}
		if !first {
			log.Printf("reconnected")
		}
		first = false
		printPath(ep)

		serveErr := serve(ctx, sess)
		_ = ep.Close()

		if ctx.Err() != nil {
			return nil
		}
		if !rf.retry {
			return serveErr
		}
		log.Printf("tunnel dropped — reconnecting over the rendezvous server...")
		if !sleepCtx(ctx, reconnectDelay) {
			return nil
		}
	}
}

// round performs one connection attempt. Candidates are gathered up front and
// carried inside the Hello frame so each round is a clean two-message
// exchange: the joiner sends first, the host responds. Roles are fixed —
// host is ICE-controlling and the QUIC client.
func (rl *rendezvousLoop) round(ctx context.Context) (*peer.Session, *icewrap.Endpoint, error) {
	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return nil, nil, err
	}
	ep, err := icewrap.New(icewrap.Config{
		STUNServers:     rl.rf.stunServers(),
		TURNServers:     rl.turns,
		IncludeLoopback: rl.rf.includeLoopback,
		RelayOnly:       rl.rf.forceRelay,
	})
	if err != nil {
		return nil, nil, err
	}
	logICEStates(ep)

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

	// Gather all candidates before exchanging (non-trickle keeps each round
	// atomic over the mailbox).
	gctx, gcancel := context.WithTimeout(ctx, rl.rf.gatherTimeout())
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
		return nil, nil, errors.New("no ICE candidates gathered (network down?)")
	}

	local := &sig.Hello{FP: hex.EncodeToString(fp[:]), Ufrag: ufrag, Pwd: pwd, Cands: marshaled}

	// Message ordering: joiner sends its Hello first, host replies. The first
	// Recv also confirms the PAKE key — a wrong room code fails to decrypt.
	var remote *sig.Hello
	if rl.isHost {
		if remote, err = rl.recvHello(ctx); err != nil {
			return nil, nil, err
		}
		if err = rl.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
	} else {
		if err = rl.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
		if remote, err = rl.recvHello(ctx); err != nil {
			return nil, nil, err
		}
	}

	fpBytes, err := hex.DecodeString(remote.FP)
	if err != nil || len(fpBytes) != 32 {
		return nil, nil, errors.New("malformed peer fingerprint")
	}
	var expectedFP xcrypto.Fingerprint
	copy(expectedFP[:], fpBytes)

	for _, raw := range remote.Cands {
		if err := ep.AddRemoteCandidate(raw); err != nil {
			log.Printf("skipping bad remote candidate: %v", err)
		}
	}

	log.Printf("connecting...")
	if rl.isHost {
		ic, err := ep.Dial(ctx, remote.Ufrag, remote.Pwd)
		if err != nil {
			return nil, nil, fmt.Errorf("ICE failed: %w", err)
		}
		sess, err := peer.EstablishQUIC(ctx, ic, true, cert, expectedFP)
		if err != nil {
			return nil, nil, fmt.Errorf("QUIC handshake: %w", err)
		}
		ok = true
		return sess, ep, nil
	}
	ic, err := ep.Accept(ctx, remote.Ufrag, remote.Pwd)
	if err != nil {
		return nil, nil, fmt.Errorf("ICE failed: %w", err)
	}
	sess, err := peer.EstablishQUIC(ctx, ic, false, cert, expectedFP)
	if err != nil {
		return nil, nil, fmt.Errorf("QUIC handshake: %w", err)
	}
	ok = true
	return sess, ep, nil
}

func (rl *rendezvousLoop) recvHello(ctx context.Context) (*sig.Hello, error) {
	t, raw, err := rl.sc.Recv(ctx)
	if err != nil {
		return nil, err
	}
	if t != sig.MsgHello {
		return nil, fmt.Errorf("expected hello frame, got %q", t)
	}
	var h sig.Hello
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("malformed hello: %w", err)
	}
	return &h, nil
}

// gatherTimeout is the per-round candidate gathering deadline.
func (r *rendezvousFlags) gatherTimeout() time.Duration { return 3 * time.Second }

// sleepCtx sleeps for d unless ctx is cancelled first; returns false if
// cancelled.
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
