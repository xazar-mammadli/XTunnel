package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

func newLoopbackEndpoint(t *testing.T) *icewrap.Endpoint {
	t.Helper()
	ep, err := icewrap.New(icewrap.Config{
		IncludeLoopback: true,
		UDP4Only:        true,
	})
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	return ep
}

func crossWire(t *testing.T, ctx context.Context, a, b *icewrap.Endpoint) (ca, cb net.Conn) {
	t.Helper()

	gctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	aCands, err := a.GatherAll(gctx)
	if err != nil {
		t.Fatalf("gather a: %v", err)
	}
	bCands, err := b.GatherAll(gctx)
	if err != nil {
		t.Fatalf("gather b: %v", err)
	}
	if len(aCands) == 0 || len(bCands) == 0 {
		t.Fatalf("no candidates gathered: a=%d b=%d", len(aCands), len(bCands))
	}
	for _, c := range aCands {
		if err := b.AddRemoteCandidate(c.Marshal()); err != nil {
			t.Fatalf("b add remote: %v", err)
		}
	}
	for _, c := range bCands {
		if err := a.AddRemoteCandidate(c.Marshal()); err != nil {
			t.Fatalf("a add remote: %v", err)
		}
	}

	aUfrag, aPwd, err := a.Credentials()
	if err != nil {
		t.Fatalf("a creds: %v", err)
	}
	bUfrag, bPwd, err := b.Credentials()
	if err != nil {
		t.Fatalf("b creds: %v", err)
	}

	type res struct {
		conn net.Conn
		err  error
	}
	aCh := make(chan res, 1)
	bCh := make(chan res, 1)
	go func() {
		c, err := a.Dial(ctx, bUfrag, bPwd)
		aCh <- res{c, err}
	}()
	go func() {
		c, err := b.Accept(ctx, aUfrag, aPwd)
		bCh <- res{c, err}
	}()
	ra, rb := <-aCh, <-bCh
	if ra.err != nil {
		t.Fatalf("ICE dial: %v", ra.err)
	}
	if rb.err != nil {
		t.Fatalf("ICE accept: %v", rb.err)
	}
	return ra.conn, rb.conn
}

func establishSessions(t *testing.T, ctx context.Context) (ctrl, ctrld *Session) {
	t.Helper()

	a := newLoopbackEndpoint(t)
	b := newLoopbackEndpoint(t)
	iceA, iceB := crossWire(t, ctx, a, b)

	certA, fpA, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, fpB, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}

	type res struct {
		s   *Session
		err error
	}
	aCh := make(chan res, 1)
	bCh := make(chan res, 1)
	go func() {
		s, err := EstablishQUIC(ctx, iceA, true, certA, fpB)
		aCh <- res{s, err}
	}()
	go func() {
		s, err := EstablishQUIC(ctx, iceB, false, certB, fpA)
		bCh <- res{s, err}
	}()
	ra, rb := <-aCh, <-bCh
	if ra.err != nil {
		t.Fatalf("QUIC establish (controlling): %v", ra.err)
	}
	if rb.err != nil {
		t.Fatalf("QUIC establish (controlled): %v", rb.err)
	}
	t.Cleanup(func() { _ = ra.s.Close(); _ = rb.s.Close() })
	return ra.s, rb.s
}

func TestQUICOverICE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctrl, ctrld := establishSessions(t, ctx)

	const total = 32 << 20
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 31)
	}

	recvDone := make(chan [32]byte, 1)
	go func() {
		st, err := ctrld.Conn.AcceptStream(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			recvDone <- [32]byte{}
			return
		}
		h := sha256.New()
		if _, err := io.Copy(h, st); err != nil {
			t.Errorf("recv copy: %v", err)
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		recvDone <- sum
	}()

	st, err := ctrl.Conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	hSend := sha256.New()
	start := time.Now()
	sent := 0
	for sent < total {
		n, err := st.Write(payload)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		hSend.Write(payload[:n])
		sent += n
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	gotSum := <-recvDone
	elapsed := time.Since(start)

	var wantSum [32]byte
	copy(wantSum[:], hSend.Sum(nil))
	if !bytes.Equal(gotSum[:], wantSum[:]) {
		t.Fatalf("integrity mismatch: got %x want %x", gotSum[:8], wantSum[:8])
	}

	mbps := float64(sent) * 8 / elapsed.Seconds() / 1e6
	t.Logf("QUIC-over-ICE loopback: %d MiB in %v = %.0f Mbps", sent>>20, elapsed.Round(time.Millisecond), mbps)
	if mbps < 100 {
		t.Errorf("throughput unexpectedly low: %.0f Mbps", mbps)
	}
}

func TestFingerprintMismatchRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	a := newLoopbackEndpoint(t)
	b := newLoopbackEndpoint(t)
	iceA, iceB := crossWire(t, ctx, a, b)

	certA, _, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, fpB, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}
	var bogus xcrypto.Fingerprint
	bogus[0] = 0xFF

	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	defer hcancel()

	aCh := make(chan error, 1)
	go func() {
		s, err := EstablishQUIC(hctx, iceA, true, certA, fpB)
		if s != nil {
			_ = s.Close()
		}
		aCh <- err
	}()
	s, err := EstablishQUIC(hctx, iceB, false, certB, bogus)
	if s != nil {
		_ = s.Close()
	}
	if err == nil {
		t.Fatal("controlled side accepted a client with wrong fingerprint")
	}
	<-aCh
}
