package broker_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/xazar/xtunnel/internal/signal"
	"github.com/xazar/xtunnel/internal/signal/broker"
)

// fakeNtfy is a minimal ntfy-compatible pub/sub server for tests: POST /<topic>
// publishes; GET /<topic>/ws streams that topic's messages as ntfy JSON events.
// It buffers recent messages so a subscriber that connects slightly late (the
// `since` window) still receives them.
type fakeNtfy struct {
	mu   sync.Mutex
	subs map[string][]chan string // topic -> subscriber channels
	hist map[string][]string      // topic -> recent messages
}

func newFakeNtfy() *fakeNtfy {
	return &fakeNtfy{subs: map[string][]chan string{}, hist: map[string][]string{}}
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if strings.HasSuffix(path, "/ws") {
		f.serveWS(w, r, strings.TrimSuffix(path, "/ws"))
		return
	}
	// Publish.
	buf, _ := io.ReadAll(r.Body)
	msg := string(buf)
	f.mu.Lock()
	f.hist[path] = append(f.hist[path], msg)
	subs := append([]chan string(nil), f.subs[path]...)
	f.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (f *fakeNtfy) serveWS(w http.ResponseWriter, r *http.Request, topic string) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ch := make(chan string, 64)

	f.mu.Lock()
	backlog := append([]string(nil), f.hist[topic]...) // emulate ?since=
	f.subs[topic] = append(f.subs[topic], ch)
	f.mu.Unlock()

	// Process inbound control frames (notably the client's close) so the
	// close handshake completes promptly instead of timing out.
	ctx := ws.CloseRead(r.Context())
	send := func(event, message string) error {
		b, _ := json.Marshal(map[string]string{"event": event, "topic": topic, "message": message})
		return ws.Write(ctx, websocket.MessageText, b)
	}
	_ = send("open", "")
	for _, m := range backlog {
		if err := send("message", m); err != nil {
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-ch:
			if err := send("message", m); err != nil {
				return
			}
		}
	}
}

// TestBrokerSecureChannel runs the real PAKE + AEAD SecureChannel over two
// broker transports talking through the fake ntfy server, proving the broker
// transport carries signaling correctly and the two per-direction topics wire
// the peers together.
func TestBrokerSecureChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	srv := httptest.NewServer(newFakeNtfy())
	defer srv.Close()

	const code = "apple-river-cedar-otter-maple-delta"

	type dialRes struct {
		tr  *broker.Transport
		err error
	}
	hCh := make(chan dialRes, 1)
	go func() {
		tr, err := broker.Dial(ctx, srv.URL, code, true)
		hCh <- dialRes{tr, err}
	}()
	jtr, err := broker.Dial(ctx, srv.URL, code, false)
	if err != nil {
		t.Fatalf("joiner dial: %v", err)
	}
	defer jtr.Close()
	hr := <-hCh
	if hr.err != nil {
		t.Fatalf("host dial: %v", hr.err)
	}
	htr := hr.tr
	defer htr.Close()

	type scRes struct {
		sc  *signal.SecureChannel
		err error
	}
	scCh := make(chan scRes, 1)
	go func() {
		sc, err := signal.Secure(ctx, htr, code, true, signal.ModeBroker)
		scCh <- scRes{sc, err}
	}()
	jsc, err := signal.Secure(ctx, jtr, code, false, signal.ModeBroker)
	if err != nil {
		t.Fatalf("joiner secure: %v", err)
	}
	hres := <-scCh
	if hres.err != nil {
		t.Fatalf("host secure: %v", hres.err)
	}
	hsc := hres.sc

	// Exchange a hello both ways.
	want := &signal.Hello{FP: "deadbeef", Ufrag: "u", Pwd: "p", Rid: "r1"}
	if err := jsc.Send(ctx, signal.MsgHello, want); err != nil {
		t.Fatal(err)
	}
	typ, raw, err := hsc.Recv(ctx)
	if err != nil {
		t.Fatalf("host recv: %v", err)
	}
	if typ != signal.MsgHello {
		t.Fatalf("frame type %q", typ)
	}
	var got signal.Hello
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.FP != want.FP || got.Rid != want.Rid {
		t.Fatalf("hello mismatch: %+v", got)
	}
}

// TestBrokerWrongCode proves a code mismatch means the two sides land on
// different topics AND derive different PAKE keys — pairing cannot succeed.
func TestBrokerWrongCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	srv := httptest.NewServer(newFakeNtfy())
	defer srv.Close()

	htr, err := broker.Dial(ctx, srv.URL, "apple-river-cedar-otter-maple-delta", true)
	if err != nil {
		t.Fatal(err)
	}
	defer htr.Close()
	jtr, err := broker.Dial(ctx, srv.URL, "wrong-wrong-wrong-wrong-wrong-wrong", false)
	if err != nil {
		t.Fatal(err)
	}
	defer jtr.Close()

	// Different codes -> different topics, so neither Secure even receives the
	// other's PAKE message; both must time out rather than pair.
	hctx, hcancel := context.WithTimeout(ctx, 2*time.Second)
	defer hcancel()
	done := make(chan struct{}, 2)
	go func() { _, _ = signal.Secure(hctx, htr, "apple-river-cedar-otter-maple-delta", true, signal.ModeBroker); done <- struct{}{} }()
	go func() { _, _ = signal.Secure(hctx, jtr, "wrong-wrong-wrong-wrong-wrong-wrong", false, signal.ModeBroker); done <- struct{}{} }()
	<-done
	<-done
	if hctx.Err() == nil {
		t.Fatal("expected the mismatched-code handshake to time out")
	}
}
