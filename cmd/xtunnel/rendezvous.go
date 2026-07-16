package main

import (
	"context"
	"crypto/rand"
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
// reconnectTimeout is deliberately above the QUIC idle timeout (60s, see
// peer.quicConfig): a peer may take that long to notice the drop, and a round
// must stay open long enough for it to respond, so neither side re-sends an
// opener and buffers a stale frame while the other is still catching up.
const (
	reconnectTimeout = 90 * time.Second
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

	nameplate, err := mb.CreateRoom(ctx)
	if err != nil {
		return err
	}
	// The server assigns the nameplate; we add the secret words locally so the
	// server never learns the full code (the PAKE password).
	secret, err := sig.NewSecretWords()
	if err != nil {
		return err
	}
	code := nameplate + "-" + secret
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
	// The code may sit between flags (e.g. `join --server X <code> -L ...`);
	// take the first positional as the code and re-parse the flags after it.
	if code == "" && fs.NArg() > 0 {
		code = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return err
		}
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("usage: xtunnel join <room-code> --server <url> -L <local:remote>")
	}
	if !sig.ValidCode(code) {
		return fmt.Errorf("invalid pairing code %q (expected e.g. 42-apple-river-cedar)", code)
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

	// Only the nameplate goes to the server for routing; the full code
	// (including the secret words) stays local and keys the PAKE.
	if err := mb.JoinRoom(ctx, sig.Nameplate(code)); err != nil {
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
	sc, err := sig.Secure(ctx, mb, code, isHost, sig.ModeRendezvous)
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

	// Clear any frames left buffered by an aborted round before starting.
	rl.sc.Drain()

	// Message ordering: the joiner opens each round with a fresh round id; the
	// host adopts and echoes it. Either side rejects a Hello that does not
	// belong to this round, so a stale frame from an aborted round can never
	// desync the reconnect loop. The first decrypt also confirms the PAKE key —
	// a wrong code fails to decrypt.
	var remote *sig.Hello
	if rl.isHost {
		if remote, err = rl.recvOpener(ctx); err != nil {
			return nil, nil, err
		}
		local.Rid = remote.Rid
		local.Reply = true
		if err = rl.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
	} else {
		rid, rerr := randRid()
		if rerr != nil {
			return nil, nil, rerr
		}
		local.Rid = rid
		local.Reply = false
		if err = rl.sc.Send(ctx, sig.MsgHello, local); err != nil {
			return nil, nil, err
		}
		if remote, err = rl.recvReply(ctx, rid); err != nil {
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

func decodeHello(raw json.RawMessage) (*sig.Hello, error) {
	var h sig.Hello
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("malformed hello: %w", err)
	}
	return &h, nil
}

// recvOpener (host side) blocks for the joiner's round-opening Hello, then
// drains any additional buffered openers and keeps the newest — so if the
// joiner retried and buffered several openers, the host answers the current
// one rather than a stale one.
func (rl *rendezvousLoop) recvOpener(ctx context.Context) (*sig.Hello, error) {
	var latest *sig.Hello
	for latest == nil {
		t, raw, err := rl.sc.Recv(ctx)
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
		if h.Reply {
			continue // stale echo from an aborted round
		}
		latest = h
	}
	// Drain newer openers that are already buffered.
	for {
		t, raw, ok := rl.sc.TryRecv()
		if !ok {
			break
		}
		if t != sig.MsgHello {
			continue
		}
		if h, err := decodeHello(raw); err == nil && !h.Reply {
			latest = h
		}
	}
	return latest, nil
}

// recvReply (joiner side) waits for the host's reply matching this round's id,
// skipping any stale frame from an aborted round.
func (rl *rendezvousLoop) recvReply(ctx context.Context, rid string) (*sig.Hello, error) {
	for {
		t, raw, err := rl.sc.Recv(ctx)
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

// randRid returns a fresh 8-byte round identifier as hex.
func randRid() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
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
