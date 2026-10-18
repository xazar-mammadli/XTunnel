package peer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/xcrypto"
)

func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialPacketSize:              1150,
		DisablePathMTUDiscovery:        true,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow:     16 << 20,
		MaxIncomingStreams:             1 << 10,
	}
}

type Session struct {
	Conn *quic.Conn

	listener  *quic.Listener
	transport *quic.Transport
	pconn     net.PacketConn
}

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
