package relay_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/peer"
	"github.com/xazar/xtunnel/internal/relay"
	"github.com/xazar/xtunnel/internal/xcrypto"
)

// TestForcedRelay proves the M5 fallback: with both ICE agents restricted to
// relay-only candidates, a QUIC session still establishes and carries data
// through the embedded TURN server. This is the path taken when direct hole
// punching fails.
func TestForcedRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	rs, err := relay.Start(relay.Config{
		PublicIP:      "127.0.0.1",
		ListenAddr:    "127.0.0.1:0",
		Secret:        "test-secret",
		CredentialTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	defer rs.Close()

	credA, okA := rs.Issue(0)
	credB, okB := rs.Issue(0)
	if !okA || !okB {
		t.Fatal("failed to issue TURN credentials")
	}
	t.Logf("relay at %s", credA.URL)

	newRelayOnly := func(cred struct{ URL, User, Pass string }) *icewrap.Endpoint {
		ep, err := icewrap.New(icewrap.Config{
			TURNServers: []icewrap.TURNServer{{URL: cred.URL, Username: cred.User, Password: cred.Pass}},
			RelayOnly:   true, // excludes host/srflx: the only path is the relay
		})
		if err != nil {
			t.Fatalf("new relay-only endpoint: %v", err)
		}
		t.Cleanup(func() { _ = ep.Close() })
		return ep
	}

	a := newRelayOnly(struct{ URL, User, Pass string }{credA.URL, credA.Username, credA.Password})
	b := newRelayOnly(struct{ URL, User, Pass string }{credB.URL, credB.Username, credB.Password})

	// Gather relay candidates and exchange them.
	gctx, gcancel := context.WithTimeout(ctx, 15*time.Second)
	defer gcancel()
	aCands, err := a.GatherAll(gctx)
	if err != nil {
		t.Fatalf("gather a: %v", err)
	}
	bCands, err := b.GatherAll(gctx)
	if err != nil {
		t.Fatalf("gather b: %v", err)
	}
	if len(aCands) == 0 || len(bCands) == 0 {
		t.Fatalf("no relay candidates gathered: a=%d b=%d", len(aCands), len(bCands))
	}
	for _, c := range aCands {
		if err := b.AddRemoteCandidate(c.Marshal()); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range bCands {
		if err := a.AddRemoteCandidate(c.Marshal()); err != nil {
			t.Fatal(err)
		}
	}

	aUfrag, aPwd, _ := a.Credentials()
	bUfrag, bPwd, _ := b.Credentials()

	type iceRes struct {
		conn net.Conn
		err  error
	}
	aConnCh := make(chan iceRes, 1)
	bConnCh := make(chan iceRes, 1)
	go func() {
		c, err := a.Dial(ctx, bUfrag, bPwd)
		aConnCh <- iceRes{c, err}
	}()
	go func() {
		c, err := b.Accept(ctx, aUfrag, aPwd)
		bConnCh <- iceRes{c, err}
	}()

	ra, rb := <-aConnCh, <-bConnCh
	if ra.err != nil {
		t.Fatalf("ICE dial over relay: %v", ra.err)
	}
	if rb.err != nil {
		t.Fatalf("ICE accept over relay: %v", rb.err)
	}
	iceA, iceB := ra.conn, rb.conn

	// Confirm the nominated pair really is relayed.
	if pair, err := a.SelectedPair(); err == nil && pair != nil {
		t.Logf("nominated: local=%s remote=%s", pair.Local.Type(), pair.Remote.Type())
	}

	certA, fpA, _ := xcrypto.GenerateCert()
	certB, fpB, _ := xcrypto.GenerateCert()

	sessCh := make(chan *peer.Session, 2)
	errCh := make(chan error, 2)
	go func() {
		s, err := peer.EstablishQUIC(ctx, iceA, true, certA, fpB)
		if err != nil {
			errCh <- err
			return
		}
		sessCh <- s
	}()
	go func() {
		s, err := peer.EstablishQUIC(ctx, iceB, false, certB, fpA)
		if err != nil {
			errCh <- err
			return
		}
		sessCh <- s
	}()

	var sessions []*peer.Session
	for len(sessions) < 2 {
		select {
		case s := <-sessCh:
			sessions = append(sessions, s)
		case err := <-errCh:
			t.Fatalf("QUIC over relay failed: %v", err)
		}
	}
	defer sessions[0].Close()
	defer sessions[1].Close()

	// Send a message through the relayed QUIC stream.
	recvCh := make(chan []byte, 1)
	go func() {
		st, err := sessions[1].Conn.AcceptStream(ctx)
		if err != nil {
			recvCh <- nil
			return
		}
		buf, _ := io.ReadAll(st)
		recvCh <- buf
	}()

	st, err := sessions[0].Conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("relayed-hello")
	if _, err := st.Write(want); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	got := <-recvCh
	if string(got) != string(want) {
		t.Fatalf("relayed payload mismatch: got %q want %q", got, want)
	}
	t.Log("QUIC-over-TURN relay round trip OK")
}
