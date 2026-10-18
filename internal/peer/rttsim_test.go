package peer

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

type simConn struct {
	rx     chan simPkt
	peerRx chan simPkt
	oneWay time.Duration
	local  net.Addr
	remote net.Addr

	closeOnce sync.Once
	closed    chan struct{}

	mu           sync.Mutex
	readDeadline time.Time
	dlChanged    chan struct{}
}

type simPkt struct {
	data []byte
	at   time.Time
}

func newSimPair(rtt time.Duration) (*simConn, *simConn) {
	chA := make(chan simPkt, 16384)
	chB := make(chan simPkt, 16384)
	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 1}
	a := &simConn{rx: chA, peerRx: chB, oneWay: rtt / 2, local: addrA, remote: addrB, closed: make(chan struct{}), dlChanged: make(chan struct{})}
	b := &simConn{rx: chB, peerRx: chA, oneWay: rtt / 2, local: addrB, remote: addrA, closed: make(chan struct{}), dlChanged: make(chan struct{})}
	return a, b
}

func (c *simConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dl, dlChanged := c.readDeadline, c.dlChanged
		c.mu.Unlock()

		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			timeout = timer.C
		}

		select {
		case pkt := <-c.rx:
			if d := time.Until(pkt.at); d > time.Millisecond {
				time.Sleep(d)
			}
			n := copy(b, pkt.data)
			return n, c.remote, nil
		case <-c.closed:
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-dlChanged:
		}
	}
}

func (c *simConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case c.peerRx <- simPkt{data: data, at: time.Now().Add(c.oneWay)}:
	default:
	}
	return len(b), nil
}

func (c *simConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *simConn) LocalAddr() net.Addr { return c.local }

func (c *simConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.dlChanged)
	c.dlChanged = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *simConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *simConn) SetWriteDeadline(time.Time) error { return nil }

func TestQUICSimulatedRTT(t *testing.T) {
	if testing.Short() {
		t.Skip("RTT simulation takes several seconds")
	}
	for _, rtt := range []time.Duration{20 * time.Millisecond, 100 * time.Millisecond} {
		t.Run(rtt.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			pcA, pcB := newSimPair(rtt)
			defer pcA.Close()
			defer pcB.Close()

			certA, fpA, err := xcrypto.GenerateCert()
			if err != nil {
				t.Fatal(err)
			}
			certB, fpB, err := xcrypto.GenerateCert()
			if err != nil {
				t.Fatal(err)
			}

			trB := &quic.Transport{Conn: pcB}
			defer trB.Close()
			ln, err := trB.Listen(xcrypto.ServerTLS(certB, fpA), quicConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			type recvRes struct {
				n   int64
				err error
			}
			recvCh := make(chan recvRes, 1)
			go func() {
				conn, err := ln.Accept(ctx)
				if err != nil {
					recvCh <- recvRes{0, err}
					return
				}
				st, err := conn.AcceptStream(ctx)
				if err != nil {
					recvCh <- recvRes{0, err}
					return
				}
				n, err := io.Copy(io.Discard, st)
				recvCh <- recvRes{n, err}
			}()

			trA := &quic.Transport{Conn: pcA}
			defer trA.Close()
			conn, err := trA.Dial(ctx, pcB.LocalAddr(), xcrypto.ClientTLS(certA, fpB), quicConfig())
			if err != nil {
				t.Fatalf("dial over %v RTT: %v", rtt, err)
			}
			defer conn.CloseWithError(0, "done")

			st, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}

			const total = 64 << 20
			payload := make([]byte, 256<<10)
			start := time.Now()
			sent := 0
			for sent < total {
				n, err := st.Write(payload)
				if err != nil {
					t.Fatalf("write after %d bytes: %v", sent, err)
				}
				sent += n
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			res := <-recvCh
			elapsed := time.Since(start)
			if res.err != nil {
				t.Fatalf("receiver: %v", res.err)
			}
			if res.n != total {
				t.Fatalf("received %d of %d bytes", res.n, total)
			}

			mbps := float64(total) * 8 / elapsed.Seconds() / 1e6
			t.Logf("QUIC @ %v RTT: %d MiB in %v = %.0f Mbps (SCTP reference @100ms: ~45 Mbps)",
				rtt, total>>20, elapsed.Round(time.Millisecond), mbps)
			if mbps < 100 {
				t.Errorf("throughput below 100 Mbps at %v RTT: %.0f", rtt, mbps)
			}
		})
	}
}
