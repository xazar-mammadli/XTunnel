package main

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

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/peer"
)

// fakeNtfy is a minimal ntfy-compatible pub/sub server for the broker e2e:
// POST /<topic> publishes; GET /<topic>/ws streams that topic's messages,
// replaying recent history to emulate ntfy's `since` window.
type fakeNtfy struct {
	mu   sync.Mutex
	subs map[string][]chan string
	hist map[string][]string
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
	backlog := append([]string(nil), f.hist[topic]...)
	f.subs[topic] = append(f.subs[topic], ch)
	f.mu.Unlock()

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

// TestBrokerPairE2E drives the full broker-mode pairing at the CLI core level:
// two brokerPair calls (offerer + answerer) meet through a local fake ntfy,
// run PAKE + ICE + QUIC over loopback, and the resulting sessions carry data.
func TestBrokerPairE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv := httptest.NewServer(newFakeNtfy())
	defer srv.Close()

	const code = "apple-river-cedar-otter-maple-delta"
	mf := &manualFlags{
		signalURL:       srv.URL,
		includeLoopback: true,
		pairTimeout:     30 * time.Second,
		stun:            stringList{}, // loopback host candidates suffice
	}

	type res struct {
		sess *peer.Session
		ep   *icewrap.Endpoint
		err  error
	}
	// offerer (host)
	hCh := make(chan res, 1)
	go func() {
		sess, ep, err := brokerPair(ctx, code, true, mf)
		hCh <- res{sess, ep, err}
	}()
	// answerer (joiner)
	jsess, jep, jerr := brokerPair(ctx, code, false, mf)
	hr := <-hCh
	if jerr != nil {
		t.Fatalf("answerer brokerPair: %v", jerr)
	}
	if hr.err != nil {
		t.Fatalf("offerer brokerPair: %v", hr.err)
	}
	defer hr.sess.Close()
	defer hr.ep.Close()
	defer jsess.Close()
	defer jep.Close()

	pingSession(t, ctx, hr.sess, jsess, "broker-mode-hello")
}
