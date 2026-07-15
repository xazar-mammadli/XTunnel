package icewrap

import (
	"net"
	"time"
)

// SyntheticRemote is the fixed pseudo-address both peers use for the single
// remote behind an ICE conn. quic-go tracks peers by address; with exactly
// one remote per transport, a stable synthetic address is sufficient and
// hides ICE path switches (direct <-> relay) from QUIC entirely.
// 198.51.100.0/24 is TEST-NET-2, never routable.
var SyntheticRemote net.Addr = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4242}

// PacketConn presents a message-oriented net.Conn (each Read returns one
// datagram — exactly ice.Conn's contract) as a net.PacketConn suitable for
// quic.Transport.
type PacketConn struct {
	inner net.Conn
}

// WrapPacketConn adapts an established ICE conn for quic-go.
func WrapPacketConn(c net.Conn) *PacketConn { return &PacketConn{inner: c} }

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.inner.Read(b)
	return n, SyntheticRemote, err
}

func (p *PacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.inner.Write(b)
}

func (p *PacketConn) Close() error                       { return p.inner.Close() }
func (p *PacketConn) LocalAddr() net.Addr                { return p.inner.LocalAddr() }
func (p *PacketConn) SetDeadline(t time.Time) error      { return p.inner.SetDeadline(t) }
func (p *PacketConn) SetReadDeadline(t time.Time) error  { return p.inner.SetReadDeadline(t) }
func (p *PacketConn) SetWriteDeadline(t time.Time) error { return p.inner.SetWriteDeadline(t) }
