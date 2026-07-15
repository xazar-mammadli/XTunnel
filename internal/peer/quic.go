// Package peer establishes the encrypted QUIC session over an ICE path and
// defines the role convention used everywhere in xtunnel:
//
//	offer creator / room creator (host) = ICE controlling = QUIC client
//	answerer / joiner                   = ICE controlled  = QUIC server
package peer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/xcrypto"
)

// quicConfig returns the tuned QUIC configuration shared by both roles.
//
// InitialPacketSize is capped at 1150 and PMTUD is disabled: the ICE path may
// traverse a TURN relay whose ChannelData framing adds 4 bytes, and the path
// can switch between direct and relay after an ICE restart, so we always
// assume the tighter MTU. Receive windows are raised well above quic-go
// defaults so a single tunnel stream can fill high-BDP paths.
func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:             60 * time.Second,
		KeepAlivePeriod:            15 * time.Second,
		InitialPacketSize:          1150,
		DisablePathMTUDiscovery:    true,
		InitialStreamReceiveWindow:     1 << 20,  // 1 MiB
		MaxStreamReceiveWindow:         8 << 20,  // 8 MiB
		InitialConnectionReceiveWindow: 2 << 20,  // 2 MiB
		MaxConnectionReceiveWindow:     16 << 20, // 16 MiB
		MaxIncomingStreams:             1 << 10,
	}
}

// Session bundles the QUIC connection with the resources standing behind it,
// so a single Close tears down the whole stack in order.
type Session struct {
	Conn *quic.Conn

	listener  *quic.Listener
	transport *quic.Transport
	pconn     net.PacketConn
}

// Close shuts the QUIC connection and the underlying ICE socket.
func (s *Session) Close() error {
	if s.Conn != nil {
		_ = s.Conn.CloseWithError(0, "bye")
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	if s.pconn != nil {
		return s.pconn.Close()
	}
	return nil
}

// EstablishQUIC runs the QUIC/TLS 1.3 handshake over an established ICE conn.
// controlling peers dial; controlled peers listen and accept exactly one
// connection. The remote leaf certificate is pinned to expectedFP.
func EstablishQUIC(
	ctx context.Context,
	iceConn net.Conn,
	controlling bool,
	cert tls.Certificate,
	expectedFP xcrypto.Fingerprint,
) (*Session, error) {
	pconn := icewrap.WrapPacketConn(iceConn)
	transport := &quic.Transport{Conn: pconn}
	sess := &Session{transport: transport, pconn: pconn}

	if controlling {
		conn, err := transport.Dial(ctx, icewrap.SyntheticRemote, xcrypto.ClientTLS(cert, expectedFP), quicConfig())
		if err != nil {
			_ = sess.Close()
			return nil, fmt.Errorf("QUIC dial: %w", err)
		}
		sess.Conn = conn
		return sess, nil
	}

	ln, err := transport.Listen(xcrypto.ServerTLS(cert, expectedFP), quicConfig())
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("QUIC listen: %w", err)
	}
	sess.listener = ln
	conn, err := ln.Accept(ctx)
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("QUIC accept: %w", err)
	}
	sess.Conn = conn
	return sess, nil
}
