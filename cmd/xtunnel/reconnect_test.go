package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/mailbox"
	"github.com/xazar-mammadli/XTunnel/internal/peer"
	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

func testOptions() *options {
	return &options{includeLoopback: true, stun: stringList{}, timeout: 30 * time.Second}
}

func quietConsole() *console {
	return &console{out: io.Discard, err: io.Discard}
}

func startMailbox(t *testing.T) string {
	t.Helper()
	mbSrv := mailbox.New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", mbSrv.HandleWS)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://")
}

func pairMailboxes(t *testing.T, ctx context.Context, url string) (host, join *sig.Mailbox, code string) {
	t.Helper()
	host, nameplate, err := sig.Create(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	join, err = sig.Join(ctx, url, nameplate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = join.Close() })
	if err := host.WaitPeer(ctx); err != nil {
		t.Fatal(err)
	}
	return host, join, nameplate + "-000000"
}

func startEcho(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func buildLoop(t *testing.T, ctx context.Context, mb *sig.Mailbox, code string, isHost bool) *loop {
	t.Helper()
	sc, err := sig.Secure(ctx, mb, code, isHost)
	if err != nil {
		t.Fatalf("secure (host=%v): %v", isHost, err)
	}
	return &loop{sc: sc, o: testOptions(), isHost: isHost, out: quietConsole()}
}

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

func doRound(t *testing.T, ctx context.Context, host, join *loop) (hSess, jSess *peer.Session, hEp, jEp *icewrap.Endpoint) {
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

func TestRendezvousReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hostMB, joinMB, code := pairMailboxes(t, ctx, startMailbox(t))

	hlCh := make(chan *loop, 1)
	go func() { hlCh <- buildLoop(t, ctx, hostMB, code, true) }()
	joinLoop := buildLoop(t, ctx, joinMB, code, false)
	hostLoop := <-hlCh

	h1, j1, hEp1, jEp1 := doRound(t, ctx, hostLoop, joinLoop)
	pingSession(t, ctx, h1, j1, "round-1-hello")
	_ = h1.Close()
	_ = j1.Close()
	_ = hEp1.Close()
	_ = jEp1.Close()

	h2, j2, hEp2, jEp2 := doRound(t, ctx, hostLoop, joinLoop)
	defer func() { _ = h2.Close(); _ = j2.Close(); _ = hEp2.Close(); _ = jEp2.Close() }()
	pingSession(t, ctx, h2, j2, "round-2-after-reconnect")
}

func TestSignaledShareConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hostMB, joinMB, code := pairMailboxes(t, ctx, startMailbox(t))
	echoPort := startEcho(t)
	o := testOptions()
	o.noRetry = true

	hostCtx, stopHost := context.WithCancel(ctx)
	defer stopHost()
	hostErr := make(chan error, 1)
	go func() {
		hostErr <- runSignaled(hostCtx, hostMB, code, true, o, quietConsole(), func(ctx context.Context, s *peer.Session) error {
			return serveHost(ctx, s, []uint16{echoPort}, quietConsole())
		})
	}()

	err := runSignaled(ctx, joinMB, code, false, o, quietConsole(), func(ctx context.Context, s *peer.Session) error {
		defer s.Close()
		j, err := tunnel.StartJoin(ctx, s.Conn, []tunnel.Forward{{Listen: "127.0.0.1:0", Port: echoPort}}, nil)
		if err != nil {
			return err
		}
		defer j.Close()
		c, err := net.Dial("tcp", j.Addrs()[0].String())
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return err
		}
		if string(buf) != "ping" {
			t.Fatalf("echo mismatch: %q", buf)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("connect side: %v", err)
	}
	stopHost()
	if err := <-hostErr; err != nil {
		t.Fatalf("share side: %v", err)
	}
}

func TestEarlyOpenerIsNotDropped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hostMB, joinMB, code := pairMailboxes(t, ctx, startMailbox(t))

	hlCh := make(chan *loop, 1)
	go func() { hlCh <- buildLoop(t, ctx, hostMB, code, true) }()
	joinLoop := buildLoop(t, ctx, joinMB, code, false)
	hostLoop := <-hlCh

	type res struct {
		s   *peer.Session
		ep  *icewrap.Endpoint
		err error
	}
	rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
	defer rcancel()
	jCh := make(chan res, 1)
	go func() { s, ep, err := joinLoop.round(rctx); jCh <- res{s, ep, err} }()
	time.Sleep(time.Second)

	hs, hep, herr := hostLoop.round(rctx)
	jr := <-jCh
	if herr != nil || jr.err != nil {
		t.Fatalf("an opener sent before the host started its round was lost: host=%v join=%v", herr, jr.err)
	}
	defer func() { _ = hs.Close(); _ = jr.s.Close(); _ = hep.Close(); _ = jr.ep.Close() }()
	pingSession(t, ctx, hs, jr.s, "early-opener")
}
