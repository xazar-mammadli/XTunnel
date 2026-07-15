package signal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xazar/xtunnel/internal/mailbox"
	"github.com/xazar/xtunnel/internal/signal"
)

// startServer runs the real xtunneld mailbox on an httptest listener.
func startServer(t *testing.T) string {
	t.Helper()
	mb := mailbox.New()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", mb.HandleWS)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://")
}

// pairedBoxes creates a room and joins it, returning both mailbox clients.
func pairedBoxes(t *testing.T, ctx context.Context, url string) (host, join *signal.Mailbox, code string) {
	t.Helper()
	h, err := signal.DialMailbox(ctx, url)
	if err != nil {
		t.Fatalf("dial host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	code, err = h.CreateRoom(ctx)
	if err != nil {
		t.Fatalf("create room: %v", err)
	}
	if !signal.ValidRoomCode(code) {
		t.Fatalf("generated code %q fails validation", code)
	}

	j, err := signal.DialMailbox(ctx, url)
	if err != nil {
		t.Fatalf("dial join: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	if err := j.JoinRoom(ctx, code); err != nil {
		t.Fatalf("join room: %v", err)
	}
	if err := h.WaitPeer(ctx); err != nil {
		t.Fatalf("wait peer: %v", err)
	}
	return h, j, code
}

// TestSecureChannelExchange runs the full PAKE + AEAD flow through the real
// mailbox server and exchanges typed frames both ways.
func TestSecureChannelExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := startServer(t)
	h, j, code := pairedBoxes(t, ctx, url)

	type res struct {
		sc  *signal.SecureChannel
		err error
	}
	hCh := make(chan res, 1)
	go func() {
		sc, err := signal.Secure(ctx, h, code, true)
		hCh <- res{sc, err}
	}()
	scJ, err := signal.Secure(ctx, j, code, false)
	if err != nil {
		t.Fatalf("join secure: %v", err)
	}
	hr := <-hCh
	if hr.err != nil {
		t.Fatalf("host secure: %v", hr.err)
	}
	scH := hr.sc

	// Host -> join hello.
	want := &signal.Hello{FP: "aabb", Ufrag: "ufragH", Pwd: "pwdH"}
	if err := scH.Send(ctx, signal.MsgHello, want); err != nil {
		t.Fatal(err)
	}
	typ, raw, err := scJ.Recv(ctx)
	if err != nil {
		t.Fatalf("join recv: %v", err)
	}
	if typ != signal.MsgHello {
		t.Fatalf("got frame type %q", typ)
	}
	var got signal.Hello
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != *want {
		t.Fatalf("hello mismatch: %+v != %+v", got, *want)
	}

	// Join -> host: several candidate frames, exercising the nonce counter.
	sent := []string{"candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host", "candidate:2 1 udp 1 8.8.8.8 6000 typ srflx", ""}
	for _, c := range sent[:2] {
		if err := scJ.Send(ctx, signal.MsgCand, &signal.Cand{C: c}); err != nil {
			t.Fatal(err)
		}
	}
	if err := scJ.Send(ctx, signal.MsgCand, &signal.Cand{End: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		typ, raw, err := scH.Recv(ctx)
		if err != nil {
			t.Fatalf("host recv %d: %v", i, err)
		}
		if typ != signal.MsgCand {
			t.Fatalf("frame %d: type %q", i, typ)
		}
		var c signal.Cand
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if i < 2 && c.C != sent[i] {
			t.Fatalf("candidate %d mismatch: %q != %q", i, c.C, sent[i])
		}
		if i == 2 && !c.End {
			t.Fatalf("frame 2 should be End marker")
		}
	}
}

// TestSecureChannelWrongCode proves that mismatched room codes derive
// different PAKE keys, so the first decrypt fails and pairing aborts —
// the property that keeps a malicious server to one online guess.
func TestSecureChannelWrongCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := startServer(t)
	h, j, code := pairedBoxes(t, ctx, url)

	type res struct {
		sc  *signal.SecureChannel
		err error
	}
	hCh := make(chan res, 1)
	go func() {
		sc, err := signal.Secure(ctx, h, code, true)
		hCh <- res{sc, err}
	}()
	// Joiner uses a DIFFERENT code than the host.
	scJ, jerr := signal.Secure(ctx, j, code+"-wrong", false)
	hr := <-hCh

	// PAKE derives keys regardless; the mismatch must surface no later than
	// the first authenticated frame. Send a hello from the host and require
	// the joiner's Recv (or its Secure) to fail.
	if jerr != nil {
		return // failed already during PAKE confirmation — acceptable
	}
	if hr.err != nil {
		return
	}
	if err := hr.sc.Send(ctx, signal.MsgHello, &signal.Hello{FP: "aa"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scJ.Recv(ctx); err == nil {
		t.Fatal("joiner decrypted a frame despite using the wrong room code")
	}
}

// TestJoinNonexistentRoom rejects a well-formed but unknown code.
func TestJoinNonexistentRoom(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := startServer(t)
	j, err := signal.DialMailbox(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.JoinRoom(ctx, "42-zebra-comet"); err == nil {
		t.Fatal("expected error joining a nonexistent room")
	}
}

// TestRoomCodeRoundTrip sanity-checks the code generator against its validator.
func TestRoomCodeRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		c, err := signal.NewRoomCode()
		if err != nil {
			t.Fatal(err)
		}
		if !signal.ValidRoomCode(c) {
			t.Fatalf("generated code %q fails ValidRoomCode", c)
		}
	}
	for _, bad := range []string{"", "zebra-comet", "1-Zebra-comet", "999-a-b", "1-a-b-c", strings.Repeat("1", 40)} {
		if signal.ValidRoomCode(bad) {
			t.Errorf("ValidRoomCode(%q) should be false", bad)
		}
	}
}