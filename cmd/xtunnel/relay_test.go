package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/peer"
	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

func relayURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("XTUNNEL_TEST_RELAY")
	if u == "" {
		t.Skip("set XTUNNEL_TEST_RELAY to a running relay (npx wrangler dev) to run relay tests")
	}
	return u
}

func TestRelayShareConnect(t *testing.T) {
	url := relayURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hostMB, joinMB, code := pairMailboxes(t, ctx, url)
	if hostMB.Reconnect() || joinMB.Reconnect() {
		t.Fatal("the relay must not advertise reconnect")
	}
	if len(hostMB.TURNServers()) != 0 || len(joinMB.TURNServers()) != 0 {
		t.Fatal("the relay must not hand out TURN credentials")
	}
	echoPort := startEcho(t)
	o := testOptions()

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
		payload := strings.Repeat("relay", 1000)
		if _, err := io.WriteString(c, payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(c, buf); err != nil {
			return err
		}
		if string(buf) != payload {
			t.Fatal("echo through the tunnel does not match")
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

func TestRelayRejections(t *testing.T) {
	url := relayURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var de *sig.DialError
	if _, err := sig.Join(ctx, url, "99998"); !errors.As(err, &de) || de.Status != http.StatusNotFound || !strings.HasPrefix(de.Body, "no such room") {
		t.Fatalf("unknown room: got %v", err)
	}
	if !strings.Contains(friendly(&sig.DialError{Status: http.StatusNotFound, Body: de.Body}), "does not exist") {
		t.Fatal("unknown room should map to a friendly message")
	}

	host, nameplate, err := sig.Create(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := sig.Join(ctx, url, nameplate)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.WaitPeer(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sig.Join(ctx, url, nameplate); !errors.As(err, &de) || de.Status != http.StatusConflict {
		t.Fatalf("third peer: got %v", err)
	}

	_ = join.Close()
	_, err = host.Recv(ctx)
	if !errors.Is(err, sig.ErrPeerLeft) {
		t.Fatalf("host should see the joiner leave, got %v", err)
	}
}

func TestRelayMessageLimit(t *testing.T) {
	url := relayURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host, join, _ := pairMailboxes(t, ctx, url)

	go func() {
		for i := 0; i < 64; i++ {
			if host.Send(ctx, []byte("spam")) != nil {
				return
			}
		}
	}()
	var lastErr error
	for i := 0; i < 64; i++ {
		if _, err := join.Recv(ctx); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("the relay should cut off a peer that floods the room")
	}
}

func TestRelayUnpairedRoomExpires(t *testing.T) {
	url := relayURL(t)
	if os.Getenv("XTUNNEL_TEST_RELAY_SHORT_TTL") == "" {
		t.Skip("start the relay with --var UNPAIRED_TTL_MS:2000 and set XTUNNEL_TEST_RELAY_SHORT_TTL=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host, _, err := sig.Create(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	var se *sig.ServerError
	if err := host.WaitPeer(ctx); !errors.As(err, &se) || se.Msg != "room expired" {
		t.Fatalf("expected the room to expire, got %v", err)
	}
}
