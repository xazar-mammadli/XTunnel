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

const Version = 1

const (
	StatusOK          = 0x00
	StatusPortRefused = 0x01
	StatusDialFailed  = 0x02
)

const ctrlRegistry = 0x01

const (
	errCodeTCPReset  quic.StreamErrorCode = 0x01
	errCodeRefused   quic.StreamErrorCode = 0x02
	errCodeBadHeader quic.StreamErrorCode = 0x03
)

const headerTimeout = 10 * time.Second

type Logf func(format string, args ...any)

func nopLog(string, ...any) {}

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
		closeStream(st, errCodeBadHeader)
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	if hdr[0] != Version {
		logf("stream %d: unsupported protocol version %d", st.StreamID(), hdr[0])
		closeStream(st, errCodeBadHeader)
		return
	}
	port := binary.BigEndian.Uint16(hdr[1:])

	if !allowed[port] {
		logf("refused connection to non-shared port %d", port)
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

type Forward struct {
	Listen string
	Port   uint16
}

type ListenError struct {
	Addr string
	Port uint16
	Err  error
}

func (e *ListenError) Error() string { return fmt.Sprintf("listen %s: %v", e.Addr, e.Err) }

func (e *ListenError) Unwrap() error { return e.Err }

func SamePortForwards(ports []uint16) []Forward {
	forwards := make([]Forward, len(ports))
	for i, p := range ports {
		forwards[i] = Forward{Listen: fmt.Sprintf("127.0.0.1:%d", p), Port: p}
	}
	return forwards
}

type Join struct {
	conn      *quic.Conn
	forwards  []Forward
	listeners []net.Listener
	remote    []uint16
	done      chan error
}

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

	if len(forwards) == 0 {
		forwards = SamePortForwards(remote)
	}
	advertised := make(map[uint16]bool, len(remote))
	for _, p := range remote {
		advertised[p] = true
	}

	j := &Join{conn: conn, forwards: forwards, remote: remote, done: make(chan error, 1)}
	for _, f := range forwards {
		if !advertised[f.Port] {
			logf("warning: the other side does not share port %d (shared: %v)", f.Port, remote)
		}
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			_ = j.Close()
			return nil, &ListenError{Addr: f.Listen, Port: f.Port, Err: err}
		}
		j.listeners = append(j.listeners, ln)
		go j.acceptLoop(ctx, ln, f.Port, logf)
	}

	go func() {
		<-conn.Context().Done()
		j.done <- context.Cause(conn.Context())
	}()
	return j, nil
}

func (j *Join) RemotePorts() []uint16 { return j.remote }

func (j *Join) Forwards() []Forward { return j.forwards }

func (j *Join) Addrs() []net.Addr {
	addrs := make([]net.Addr, len(j.listeners))
	for i, ln := range j.listeners {
		addrs[i] = ln.Addr()
	}
	return addrs
}

func (j *Join) Wait() error { return <-j.done }

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
			return
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
		logf("port %d: no status from the other side: %v", port, err)
		closeStream(st, errCodeBadHeader)
		_ = tcp.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	switch status[0] {
	case StatusOK:
	case StatusPortRefused:
		logf("port %d: refused, the other side does not share it", port)
		closeStream(st, errCodeRefused)
		_ = tcp.Close()
		return
	default:
		logf("port %d: nothing is listening on that port on the other side", port)
		closeStream(st, errCodeRefused)
		_ = tcp.Close()
		return
	}

	proxy(st, tcp)
}

func closeStream(st *quic.Stream, code quic.StreamErrorCode) {
	st.CancelRead(code)
	st.CancelWrite(code)
}

func proxy(st *quic.Stream, tcp *net.TCPConn) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(st, tcp)
		if err == nil {
			_ = st.Close()
		} else {
			st.CancelWrite(errCodeTCPReset)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(tcp, st)
		if err == nil {
			_ = tcp.CloseWrite()
		} else {
			var serr *quic.StreamError
			if errors.As(err, &serr) {
				_ = tcp.Close()
			}
			st.CancelRead(errCodeTCPReset)
			_ = tcp.CloseWrite()
		}
	}()

	<-done
	<-done
	_ = tcp.Close()
}
