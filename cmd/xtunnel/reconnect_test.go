package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/mailbox"
	"github.com/xazar/xtunnel/internal/peer"
	sig "github.com/xazar/xtunnel/internal/signal"
)

// buildLoop pairs a mailbox client, runs PAKE, and returns a ready loop.
func buildLoop(t *testing.T, ctx context.Context, mb *sig.Mailbox, code string, isHost bool) *rendezvousLoop {
	t.Helper()
	sc, err := sig.Secure(ctx, mb, code, isHost, sig.ModeRendezvous)
	if err != nil {
		t.Fatalf("secure (host=%v): %v", isHost, err)
	}
	rf := &rendezvousFlags{includeLoopback: true, stun: stringList{}}
	return &rendezvousLoop{sc: sc, rf: rf, isHost: isHost}
}

// pingSession opens a stream on the controlling side and echoes one message on
// the controlled side, proving the reconnected QUIC session carries data.
func pingSession(t *testing.T, ctx context.Context, host, join *peer.Session, msg string) {
	t.Helper()
	recv := make(chan string, 1)
	go func() {
		st, err := join.Conn.AcceptStream(ctx)
		if err != nil {
			recv <- "accept-error"
			return
		}
		buf, _ := io.ReadAll(st)
		recv <- string(buf)
	}()
	st, err := host.Conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := st.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = st.Close()
	select {
	case got := <-recv:
		if got != msg {
			t.Fatalf("session data mismatch: got %q want %q", got, msg)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for session data")
	}
}

// doRound runs one round() on both loops concurrently and returns both sessions.
func doRound(t *testing.T, ctx context.Context, host, join *rendezvousLoop) (hSess, jSess *peer.Session, hEp, jEp *icewrap.Endpoint) {
	t.Helper()
	type res struct {
		s   *peer.Session
		ep  *icewrap.Endpoint
		err error
	}
	hCh := make(chan res, 1)
	jCh := make(chan res, 1)
	go func() { s, ep, err := host.round(ctx); hCh <- res{s, ep, err} }()
	go func() { s, ep, err := join.round(ctx); jCh <- res{s, ep, err} }()
	hr, jr := <-hCh, <-jCh
	if hr.err != nil {
		t.Fatalf("host round: %v", hr.err)
	}
	if jr.err != nil {
		t.Fatalf("join round: %v", jr.err)
	}
	return hr.s, jr.s, hr.ep, jr.ep
}

// TestRendezvousReconnect proves the M6 reconnect protocol: after the first
// tunnel is established and then dropped, a second round over the SAME mailbox
// re-establishes a working QUIC session — no re-pairing, no new room code.
func TestRendezvousReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mbSrv := mailbox.New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", mbSrv.HandleWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url := "ws://" + strings.TrimPrefix(srv.URL, "http://")

	hostMB, err := sig.DialMailbox(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer hostMB.Close()
	code, err := hostMB.CreateRoom(ctx)
	if err != nil {
		t.Fatal(err)
	}
	joinMB, err := sig.DialMailbox(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer joinMB.Close()
	if err := joinMB.JoinRoom(ctx, code); err != nil {
		t.Fatal(err)
	}
	if err := hostMB.WaitPeer(ctx); err != nil {
		t.Fatal(err)
	}

	// PAKE runs once, concurrently on both sides.
	type loopRes struct {
		l *rendezvousLoop
	}
	hlCh := make(chan *rendezvousLoop, 1)
	go func() { hlCh <- buildLoop(t, ctx, hostMB, code, true) }()
	joinLoop := buildLoop(t, ctx, joinMB, code, false)
	hostLoop := <-hlCh

	// Round 1.
	h1, j1, hEp1, jEp1 := doRound(t, ctx, hostLoop, joinLoop)
	pingSession(t, ctx, h1, j1, "round-1-hello")
	t.Log("round 1 established and verified")

	// Simulate a path drop.
	_ = h1.Close()
	_ = j1.Close()
	_ = hEp1.Close()
	_ = jEp1.Close()

	// Round 2 over the same mailbox — this is the auto-reconnect path.
	h2, j2, hEp2, jEp2 := doRound(t, ctx, hostLoop, joinLoop)
	defer func() { _ = h2.Close(); _ = j2.Close(); _ = hEp2.Close(); _ = jEp2.Close() }()
	pingSession(t, ctx, h2, j2, "round-2-after-reconnect")
	t.Log("round 2 (reconnect) established and verified")
}
