package signal_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/mailbox"
	"github.com/xazar-mammadli/XTunnel/internal/signal"
)

func startServer(t *testing.T) string {
	t.Helper()
	mb := mailbox.New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", mb.HandleWS)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://")
}

func pairedBoxes(t *testing.T, ctx context.Context, url string) (host, join *signal.Mailbox, code string) {
	t.Helper()
	h, nameplate, err := signal.Create(ctx, url)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if !signal.ValidNameplate(nameplate) {
		t.Fatalf("server assigned invalid nameplate %q", nameplate)
	}
	if !h.Reconnect() {
		t.Fatal("xtunneld should advertise reconnect support")
	}

	j, err := signal.Join(ctx, url, nameplate)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	if err := h.WaitPeer(ctx); err != nil {
		t.Fatalf("wait peer: %v", err)
	}
	return h, j, nameplate + "-123456"
}

type secured struct {
	sc  *signal.SecureChannel
	err error
}

func secureBoth(ctx context.Context, h, j *signal.Mailbox, hostCode, joinCode string) (host, join secured) {
	ch := make(chan secured, 1)
	go func() {
		sc, err := signal.Secure(ctx, h, hostCode, true)
		ch <- secured{sc, err}
	}()
	sc, err := signal.Secure(ctx, j, joinCode, false)
	return <-ch, secured{sc, err}
}

func recvHello(t *testing.T, ctx context.Context, sc *signal.SecureChannel) signal.Hello {
	t.Helper()
	typ, raw, err := sc.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if typ != signal.MsgHello {
		t.Fatalf("got frame type %q", typ)
	}
	var h signal.Hello
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSecureChannelExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, j, code := pairedBoxes(t, ctx, startServer(t))
	host, join := secureBoth(ctx, h, j, code, code)
	if host.err != nil || join.err != nil {
		t.Fatalf("secure: host=%v join=%v", host.err, join.err)
	}

	want := signal.Hello{FP: "aabb", Ufrag: "ufragH", Pwd: "pwdH", Cands: []string{"candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host"}}
	if err := host.sc.Send(ctx, signal.MsgHello, &want); err != nil {
		t.Fatal(err)
	}
	if got := recvHello(t, ctx, join.sc); got.FP != want.FP || got.Ufrag != want.Ufrag || len(got.Cands) != 1 {
		t.Fatalf("hello mismatch: %+v != %+v", got, want)
	}

	for i := 0; i < 3; i++ {
		rid := string(rune('a' + i))
		if err := join.sc.Send(ctx, signal.MsgHello, &signal.Hello{Rid: rid}); err != nil {
			t.Fatal(err)
		}
		if got := recvHello(t, ctx, host.sc); got.Rid != rid {
			t.Fatalf("frame %d: rid %q, want %q", i, got.Rid, rid)
		}
	}
}

func TestSecureChannelWrongCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, j, code := pairedBoxes(t, ctx, startServer(t))
	host, join := secureBoth(ctx, h, j, code, signal.Nameplate(code)+"-654321")
	if host.err != nil || join.err != nil {
		return
	}
	if err := host.sc.Send(ctx, signal.MsgHello, &signal.Hello{FP: "aa"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := join.sc.Recv(ctx)
	if !errors.Is(err, signal.ErrWrongCode) {
		t.Fatalf("expected ErrWrongCode, got %v", err)
	}
	if !errors.Is(join.sc.Err(), signal.ErrWrongCode) {
		t.Fatalf("channel should be dead with ErrWrongCode, got %v", join.sc.Err())
	}
}

func TestSecureDrainDiscardsBufferedFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, j, code := pairedBoxes(t, ctx, startServer(t))
	host, join := secureBoth(ctx, h, j, code, code)
	if host.err != nil || join.err != nil {
		t.Fatalf("secure: host=%v join=%v", host.err, join.err)
	}

	for i := 0; i < 3; i++ {
		if err := host.sc.Send(ctx, signal.MsgHello, &signal.Hello{Rid: "stale"}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, ok := join.sc.TryRecv(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no frame ever buffered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	join.sc.Drain()

	if err := host.sc.Send(ctx, signal.MsgHello, &signal.Hello{Rid: "fresh", Reply: true}); err != nil {
		t.Fatal(err)
	}
	for {
		if recvHello(t, ctx, join.sc).Rid == "fresh" {
			return
		}
	}
}

func TestJoinErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := startServer(t)

	_, err := signal.Join(ctx, url, "42")
	var se *signal.ServerError
	if !errors.As(err, &se) || !strings.HasPrefix(se.Msg, "no such room") {
		t.Fatalf("joining an unknown room: got %v", err)
	}

	h, nameplate, err := signal.Create(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	j, err := signal.Join(ctx, url, nameplate)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := signal.Join(ctx, url, nameplate); !errors.As(err, &se) || se.Msg != "room is full" {
		t.Fatalf("third peer: got %v", err)
	}
}

func TestDialErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	busy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer busy.Close()
	_, _, err := signal.Create(ctx, busy.URL)
	var de *signal.DialError
	if !errors.As(err, &de) || de.Status != http.StatusTooManyRequests {
		t.Fatalf("expected DialError with 429, got %v", err)
	}

	for _, bad := range []string{"ftp://example.com", "wss://"} {
		if _, _, err := signal.Create(ctx, bad); err == nil {
			t.Errorf("Create(%q) should fail", bad)
		}
	}
}

func TestCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		np, err := signal.NewNameplate(i % 16)
		if err != nil {
			t.Fatal(err)
		}
		if !signal.ValidNameplate(np) {
			t.Fatalf("nameplate %q fails validation", np)
		}
		secret, err := signal.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		code := np + "-" + secret
		if !signal.ValidCode(code) {
			t.Fatalf("code %q fails validation", code)
		}
		if signal.Nameplate(code) != np {
			t.Fatalf("Nameplate(%q) = %q, want %q", code, signal.Nameplate(code), np)
		}
		seen[secret] = true
	}
	if len(seen) < 450 {
		t.Fatalf("only %d distinct secrets out of 500", len(seen))
	}
	for _, short := range []string{"0", "1", "999"} {
		if !signal.ValidNameplate(short) {
			t.Errorf("ValidNameplate(%q) should be true", short)
		}
	}
	for _, bad := range []string{"", "47", "47-12345", "47-1234567", "a-123456", "123456-123456", "47-12a456", "47 123456"} {
		if signal.ValidCode(bad) {
			t.Errorf("ValidCode(%q) should be false", bad)
		}
	}
	if !signal.ValidCode("  47-905183  ") {
		t.Error("ValidCode should ignore surrounding spaces")
	}
}
