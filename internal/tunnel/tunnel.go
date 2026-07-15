// Package tunnel implements the xtunnel data plane on top of an established
// QUIC connection.
//
// Stream direction convention:
//   - The HOST (the peer sharing local ports) opens exactly one control
//     stream and advertises its exposed ports on it.
//   - The JOINER opens one bidirectional data stream per forwarded TCP
//     connection. Streams accepted by the host are therefore always data
//     streams, and the stream accepted by the joiner is always control.
//
// Data stream wire format (joiner -> host):
//
//	[1B protocol version][2B target port, big endian]
//
// host -> joiner reply: [1B status], then raw bytes both ways. TCP half-close
// maps to QUIC stream FIN; abnormal teardown maps to CancelRead/CancelWrite.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// Version is the data-plane protocol version carried in each stream header.
const Version = 1

// Data stream reply statuses.
const (
	StatusOK          = 0x00
	StatusPortRefused = 0x01
	StatusDialFailed  = 0x02
)

// Control stream message types (host -> joiner).
const (
	ctrlRegistry = 0x01
)

// QUIC error codes used on abnormal stream teardown.
const (
	errCodeTCPReset  quic.StreamErrorCode = 0x01
	errCodeRefused   quic.StreamErrorCode = 0x02
	errCodeBadHeader quic.StreamErrorCode = 0x03
)

const headerTimeout = 10 * time.Second

// Logf is a minimal logging hook so the CLI can render events its own way.
type Logf func(format string, args ...any)

func nopLog(string, ...any) {}

// ---------------------------------------------------------------------------
// Host side

// ServeHost advertises the allowed ports on the control stream, then accepts
// data streams and forwards each to 127.0.0.1:<port>. Blocks until the
// connection dies; returns the connection error.
func ServeHost(ctx context.Context, conn *quic.Conn, allowed []uint16, logf Logf) error {
	if logf == nil {
		logf = nopLog
	}
	allowedSet := make(map[uint16]bool, len(allowed))
	for _, p := range allowed {
		allowedSet[p] = true
	}

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	if err := writeRegistry(ctrl, allowed); err != nil {
		return fmt.Errorf("send registry: %w", err)
	}
	// The control stream stays open for the connection's lifetime; nothing
	// else is sent on it in protocol version 1.

	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("accept stream: %w", err)
		}
		go hostHandleStream(st, allowedSet, logf)
	}
}

func hostHandleStream(st *quic.Stream, allowed map[uint16]bool, logf Logf) {
	_ = st.SetReadDeadline(time.Now().Add(headerTimeout))
	var hdr [3]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		logf("stream %d: bad header: %v", st.StreamID(), err)
		st.CancelRead(errCodeBadHeader)
		st.CancelWrite(errCodeBadHeader)
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	if hdr[0] != Version {
		logf("stream %d: unsupported protocol version %d", st.StreamID(), hdr[0])
		st.CancelRead(errCodeBadHeader)
		st.CancelWrite(errCodeBadHeader)
		return
	}
	port := binary.BigEndian.Uint16(hdr[1:])

	if !allowed[port] {
		logf("refused connection to non-exposed port %d", port)
		_, _ = st.Write([]byte{StatusPortRefused})
		_ = st.Close()
		st.CancelRead(errCodeRefused)
		return
	}

	tcp, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), headerTimeout)
	if err != nil {
		logf("port %d: local dial failed: %v", port, err)
		_, _ = st.Write([]byte{StatusDialFailed})
		_ = st.Close()
		st.CancelRead(errCodeRefused)
		return
	}
	if _, err := st.Write([]byte{StatusOK}); err != nil {
		_ = tcp.Close()
		return
	}
	logf("port %d: connection opened", port)
	proxy(st, tcp.(*net.TCPConn))
	logf("port %d: connection closed", port)
}

func writeRegistry(w io.Writer, ports []uint16) error {
	buf := make([]byte, 0, 3+2*len(ports))
	buf = append(buf, ctrlRegistry)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ports)))
	for _, p := range ports {
		buf = binary.BigEndian.AppendUint16(buf, p)
	}
	_, err := w.Write(buf)
	return err
}

func readRegistry(r io.Reader) ([]uint16, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != ctrlRegistry {
		return nil, fmt.Errorf("unexpected control message type %d", hdr[0])
	}
	n := binary.BigEndian.Uint16(hdr[1:])
	ports := make([]uint16, n)
	buf := make([]byte, 2*int(n))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	for i := range ports {
		ports[i] = binary.BigEndian.Uint16(buf[2*i:])
	}
	return ports, nil
}

// ---------------------------------------------------------------------------
// Joiner side

// Forward maps a local listen address to a port on the host peer.
type Forward struct {
	Listen string // e.g. "127.0.0.1:15432"
	Port   uint16 // target port on the host side
}

// Join is a running joiner data plane.
type Join struct {
	conn      *quic.Conn
	listeners []net.Listener
	remote    []uint16 // ports advertised by the host
	done      chan error
}

// StartJoin reads the host's registry, opens every local listener, and starts
// forwarding. Returns once listeners are bound (fail-fast on bind errors).
func StartJoin(ctx context.Context, conn *quic.Conn, forwards []Forward, logf Logf) (*Join, error) {
	if logf == nil {
		logf = nopLog
	}

	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept control stream: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(headerTimeout))
	remote, err := readRegistry(ctrl)
	if err != nil {
		return nil, fmt.Errorf("read registry: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Time{})

	advertised := make(map[uint16]bool, len(remote))
	for _, p := range remote {
		advertised[p] = true
	}

	j := &Join{conn: conn, remote: remote, done: make(chan error, 1)}
	for _, f := range forwards {
		if !advertised[f.Port] {
			logf("warning: host does not advertise port %d (exposed: %v)", f.Port, remote)
		}
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			_ = j.Close()
			return nil, fmt.Errorf("listen %s: %w", f.Listen, err)
		}
		j.listeners = append(j.listeners, ln)
		logf("forwarding %s -> peer:%d", ln.Addr(), f.Port)
		go j.acceptLoop(ctx, ln, f.Port, logf)
	}

	// Surface connection death so the CLI can exit/reconnect.
	go func() {
		<-conn.Context().Done()
		j.done <- context.Cause(conn.Context())
	}()
	return j, nil
}

// RemotePorts lists the ports the host advertised in its registry.
func (j *Join) RemotePorts() []uint16 { return j.remote }

// Addrs returns the bound local listener addresses, in forwards order.
func (j *Join) Addrs() []net.Addr {
	addrs := make([]net.Addr, len(j.listeners))
	for i, ln := range j.listeners {
		addrs[i] = ln.Addr()
	}
	return addrs
}

// Wait blocks until the QUIC connection dies.
func (j *Join) Wait() error { return <-j.done }

// Close shuts all local listeners.
func (j *Join) Close() error {
	for _, ln := range j.listeners {
		_ = ln.Close()
	}
	return nil
}

func (j *Join) acceptLoop(ctx context.Context, ln net.Listener, port uint16, logf Logf) {
	for {
		tcp, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go j.forwardConn(ctx, tcp.(*net.TCPConn), port, logf)
	}
}

func (j *Join) forwardConn(ctx context.Context, tcp *net.TCPConn, port uint16, logf Logf) {
	st, err := j.conn.OpenStreamSync(ctx)
	if err != nil {
		logf("port %d: open stream: %v", port, err)
		_ = tcp.Close()
		return
	}

	hdr := []byte{Version, 0, 0}
	binary.BigEndian.PutUint16(hdr[1:], port)
	if _, err := st.Write(hdr); err != nil {
		logf("port %d: write header: %v", port, err)
		_ = tcp.Close()
		return
	}

	_ = st.SetReadDeadline(time.Now().Add(headerTimeout))
	var status [1]byte
	if _, err := io.ReadFull(st, status[:]); err != nil {
		logf("port %d: no status from host: %v", port, err)
		st.CancelRead(errCodeBadHeader)
		st.CancelWrite(errCodeBadHeader)
		_ = tcp.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	switch status[0] {
	case StatusOK:
	case StatusPortRefused:
		logf("port %d: refused by host (not exposed)", port)
		closeStream(st, errCodeRefused)
		_ = tcp.Close()
		return
	default:
		logf("port %d: host could not reach local service (status %d)", port, status[0])
		closeStream(st, errCodeRefused)
		_ = tcp.Close()
		return
	}

	proxy(st, tcp)
}

// closeStream drives both halves of a QUIC stream to a terminal state so
// neither the send nor the receive side lingers after an early return.
func closeStream(st *quic.Stream, code quic.StreamErrorCode) {
	st.CancelRead(code)
	st.CancelWrite(code)
}

// ---------------------------------------------------------------------------

// proxy copies bytes in both directions between a QUIC stream and a TCP conn,
// translating EOF into half-close on the other side, and blocks until both
// directions finish.
func proxy(st *quic.Stream, tcp *net.TCPConn) {
	done := make(chan struct{}, 2)

	go func() { // tcp -> stream
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(st, tcp)
		if err == nil {
			// TCP peer half-closed: propagate FIN.
			_ = st.Close()
		} else {
			st.CancelWrite(errCodeTCPReset)
		}
	}()

	go func() { // stream -> tcp
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(tcp, st)
		if err == nil {
			// Stream FIN: propagate half-close to the TCP side.
			_ = tcp.CloseWrite()
		} else {
			var serr *quic.StreamError
			if errors.As(err, &serr) {
				// Abnormal reset from the peer: hard-close TCP.
				_ = tcp.Close()
			}
			st.CancelRead(errCodeTCPReset)
			_ = tcp.CloseWrite()
		}
	}()

	<-done
	<-done
	// Both directions done: release the TCP socket. QUIC stream halves are
	// already FINed or cancelled individually.
	_ = tcp.Close()
}
