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
}

func (r *rendezvousFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.server, "server", os.Getenv("XTUNNEL_SERVER"), "xtunneld URL, e.g. wss://tunnel.example.com (or $XTUNNEL_SERVER)")
	fs.Var(&r.stun, "stun", "STUN server URI (repeatable)")
	fs.Var(&r.turn, "turn", "extra TURN relay as url,username,password (repeatable)")
	fs.DurationVar(&r.pairTimeout, "pair-timeout", 10*time.Minute, "how long to wait for the peer")
	fs.BoolVar(&r.includeLoopback, "include-loopback", false, "gather loopback candidates (same-machine testing)")
	fs.BoolVar(&r.forceRelay, "force-relay", false, "use only relay candidates (testing the TURN fallback path)")
}

func (r *rendezvousFlags) stunServers() []string {
	if len(r.stun) > 0 {
		return r.stun
	}
	return defaultSTUN
}

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
	defer wcancel()
	if err := mb.WaitPeer(wctx); err != nil {
		return fmt.Errorf("waiting for peer: %w", err)
	}
	log.Printf("peer joined, authenticating...")

	sess, ep, err := rendezvousConnect(wctx, mb, code, true, &rf)
	if err != nil {
		return err
	}
	defer ep.Close()
	printPath(ep)
	// Signaling is finished; the tunnel lives on without the server.
	_ = mb.Close()
	return serveAsHost(ctx, sess, expose)
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

	wctx, wcancel := context.WithTimeout(ctx, rf.pairTimeout)
	defer wcancel()
	sess, ep, err := rendezvousConnect(wctx, mb, code, false, &rf)
	if err != nil {
		return err
	}
	defer ep.Close()
	printPath(ep)
	_ = mb.Close()
	return serveAsJoiner(ctx, sess, forwards)
}

// rendezvousConnect runs PAKE, the encrypted signaling exchange, trickle ICE
// and the QUIC handshake. The host is ICE-controlling and the QUIC client.
func rendezvousConnect(
	ctx context.Context,
	mb *sig.Mailbox,
	code string,
	isHost bool,
	rf *rendezvousFlags,
) (*peer.Session, *icewrap.Endpoint, error) {
	sc, err := sig.Secure(ctx, mb, code, isHost)
	if err != nil {
		return nil, nil, err
	}

	cert, fp, err := xcrypto.GenerateCert()
	if err != nil {
		return nil, nil, err
	}

	// Combine user-supplied TURN relays with any the server issued during
	// CreateRoom/JoinRoom (the relay fallback path).
	turns := append([]icewrap.TURNServer(nil), rf.turn...)
	for _, t := range mb.TURNServers() {
		turns = append(turns, icewrap.TURNServer{URL: t.URL, Username: t.Username, Password: t.Password})
	}
	if len(turns) > len(rf.turn) {
		log.Printf("relay fallback available via server-issued TURN credentials")
	}

	ep, err := icewrap.New(icewrap.Config{
		STUNServers:     rf.stunServers(),
		TURNServers:     turns,
		IncludeLoopback: rf.includeLoopback,
		RelayOnly:       rf.forceRelay,
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

	// Hello exchange doubles as PAKE key confirmation: if the codes differed,
	// the first Recv fails to decrypt.
	if err := sc.Send(ctx, sig.MsgHello, &sig.Hello{
		FP:    hex.EncodeToString(fp[:]),
		Ufrag: ufrag,
		Pwd:   pwd,
	}); err != nil {
		return nil, nil, err
	}
	t, raw, err := sc.Recv(ctx)
	if err != nil {
		return nil, nil, err
	}
	if t != sig.MsgHello {
		return nil, nil, fmt.Errorf("expected hello frame, got %q", t)
	}
	var remote sig.Hello
	if err := json.Unmarshal(raw, &remote); err != nil {
		return nil, nil, fmt.Errorf("malformed hello: %w", err)
	}
	fpBytes, err := hex.DecodeString(remote.FP)
	if err != nil || len(fpBytes) != 32 {
		return nil, nil, errors.New("malformed peer fingerprint")
	}
	var expectedFP xcrypto.Fingerprint
	copy(expectedFP[:], fpBytes)

	// Trickle local candidates to the peer as they are discovered.
	if err := ep.StartGather(); err != nil {
		return nil, nil, err
	}
	go func() {
		for c := range ep.Candidates() {
			if err := sc.Send(ctx, sig.MsgCand, &sig.Cand{C: c.Marshal()}); err != nil {
				return
			}
		}
		_ = sc.Send(ctx, sig.MsgCand, &sig.Cand{End: true})
	}()

	// Consume the peer's trickled candidates until the connection succeeds.
	recvCtx, stopRecv := context.WithCancel(ctx)
	defer stopRecv()
	go func() {
		for {
			t, raw, err := sc.Recv(recvCtx)
			if err != nil {
				return
			}
			if t != sig.MsgCand {
				continue
			}
			var c sig.Cand
			if err := json.Unmarshal(raw, &c); err != nil || c.End {
				continue
			}
			if err := ep.AddRemoteCandidate(c.C); err != nil {
				log.Printf("bad remote candidate: %v", err)
			}
		}
	}()

	log.Printf("connecting...")
	if isHost {
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
