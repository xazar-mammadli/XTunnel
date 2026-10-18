package icewrap

import (
	"net"
	"time"
)

var SyntheticRemote net.Addr = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4242}

type PacketConn struct {
	inner net.Conn
}

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
