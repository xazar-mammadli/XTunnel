package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

func quicPair(t *testing.T, ctx context.Context) (clientConn, serverConn *quic.Conn) {
	t.Helper()

	certA, fpA, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, fpB, err := xcrypto.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}

	udpB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(udpB, xcrypto.ServerTLS(certB, fpA), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = udpB.Close() })

	serverCh := make(chan *quic.Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- c
	}()

	udpA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpA.Close() })
	cc, err := quic.Dial(ctx, udpA, udpB.LocalAddr(), xcrypto.ClientTLS(certA, fpB), nil)
	if err != nil {
		t.Fatal(err)
	}
	sc := <-serverCh
	if sc == nil {
		t.FailNow()
	}
	t.Cleanup(func() {
		_ = cc.CloseWithError(0, "test done")
		_ = sc.CloseWithError(0, "test done")
	})
	return cc, sc
}

func startEchoServer(t *testing.T) uint16 {
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
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func setupTunnel(t *testing.T, ctx context.Context, exposed []uint16, forwards []Forward) *Join {
	t.Helper()
	hostConn, joinConn := quicPair(t, ctx)

	go func() {
		_ = ServeHost(ctx, hostConn, exposed, t.Logf)
	}()
	j, err := StartJoin(ctx, joinConn, forwards, t.Logf)
	if err != nil {
		t.Fatalf("start join: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func TestEchoRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	echoPort := startEchoServer(t)
	j := setupTunnel(t, ctx,
		[]uint16{echoPort},
		[]Forward{{Listen: "127.0.0.1:0", Port: echoPort}},
	)

	payload := make([]byte, 4<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", j.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.Write(payload); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		_ = c.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(c)
	wg.Wait()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

func TestConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p1 := startEchoServer(t)
	p2 := startEchoServer(t)
	j := setupTunnel(t, ctx,
		[]uint16{p1, p2},
		[]Forward{
			{Listen: "127.0.0.1:0", Port: p1},
			{Listen: "127.0.0.1:0", Port: p2},
		},
	)

	const conns = 20
	var wg sync.WaitGroup
	errCh := make(chan error, conns)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := j.Addrs()[i%2].String()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				errCh <- fmt.Errorf("conn %d dial: %w", i, err)
				return
			}
			defer c.Close()
			msg := []byte("hello-" + strconv.Itoa(i))
			if _, err := c.Write(msg); err != nil {
				errCh <- fmt.Errorf("conn %d write: %w", i, err)
				return
			}
			_ = c.(*net.TCPConn).CloseWrite()
			got, err := io.ReadAll(c)
			if err != nil {
				errCh <- fmt.Errorf("conn %d read: %w", i, err)
				return
			}
			if !bytes.Equal(got, msg) {
				errCh <- fmt.Errorf("conn %d: got %q want %q", i, got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestPortRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	echoPort := startEchoServer(t)
	notExposed := echoPort + 1
	j := setupTunnel(t, ctx,
		[]uint16{echoPort},
		[]Forward{{Listen: "127.0.0.1:0", Port: notExposed}},
	)

	c, err := net.Dial("tcp", j.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("expected connection close, read %d bytes err=%v", n, err)
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func TestRegistryAndSamePortForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p1, p2 := freePort(t), freePort(t)
	j := setupTunnel(t, ctx, []uint16{p1, p2}, nil)

	got := j.RemotePorts()
	if len(got) != 2 || got[0] != p1 || got[1] != p2 {
		t.Fatalf("registry mismatch: got %v want [%d %d]", got, p1, p2)
	}
	addrs := j.Addrs()
	for i, want := range []uint16{p1, p2} {
		if addrs[i].(*net.TCPAddr).Port != int(want) {
			t.Fatalf("forward %d listens on %v, want port %d", i, addrs[i], want)
		}
	}
}

func TestSamePortForwards(t *testing.T) {
	got := SamePortForwards([]uint16{5432, 8080})
	want := []Forward{{Listen: "127.0.0.1:5432", Port: 5432}, {Listen: "127.0.0.1:8080", Port: 8080}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("forward %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestStartJoinListenError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyAddr := busy.Addr().String()

	echoPort := startEchoServer(t)
	hostConn, joinConn := quicPair(t, ctx)
	go func() { _ = ServeHost(ctx, hostConn, []uint16{echoPort}, t.Logf) }()

	_, err = StartJoin(ctx, joinConn, []Forward{{Listen: busyAddr, Port: echoPort}}, t.Logf)
	var le *ListenError
	if !errors.As(err, &le) {
		t.Fatalf("expected ListenError, got %v", err)
	}
	if le.Addr != busyAddr || le.Port != echoPort {
		t.Fatalf("ListenError fields: %+v", le)
	}
}
