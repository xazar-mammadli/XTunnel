// Package relay embeds a TURN relay in xtunneld. It provides the fallback
// path when direct hole punching fails: peers gather relay candidates from
// this server and QUIC (still end-to-end encrypted) is forwarded as opaque
// ciphertext through it.
//
// Credentials are ephemeral time-windowed TURN-REST credentials (RFC 8489
// long-term style): a short-lived username (the expiry timestamp) plus an
// HMAC password derived from a server-held shared secret. Only peers that
// obtained credentials from the mailbox can use the relay, and they expire
// automatically.
package relay

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/xazar/xtunnel/internal/signal"
)

// Config configures the embedded TURN server.
type Config struct {
	// PublicIP is the address peers will relay through (the server's public
	// IPv4). Required.
	PublicIP string
	// ListenAddr is the UDP listen address, e.g. ":3478".
	ListenAddr string
	// Realm defaults to "xtunnel".
	Realm string
	// Secret is the shared HMAC secret for credential generation. Required.
	Secret string
	// CredentialTTL is how long issued credentials remain valid. Default 1h.
	CredentialTTL time.Duration
}

// Server is a running embedded TURN relay.
type Server struct {
	turn     *turn.Server
	conn     net.PacketConn
	publicIP string
	port     int
	realm    string
	secret   string
	ttl      time.Duration
}

// Start binds the UDP listener and starts the TURN server.
func Start(cfg Config) (*Server, error) {
	if cfg.PublicIP == "" {
		return nil, fmt.Errorf("relay: PublicIP is required")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("relay: Secret is required")
	}
	ip := net.ParseIP(cfg.PublicIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("relay: PublicIP %q is not a valid IPv4 address", cfg.PublicIP)
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "xtunnel"
	}
	ttl := cfg.CredentialTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":3478"
	}

	conn, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("relay: listen %s: %w", listenAddr, err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port

	logger := logging.NewDefaultLoggerFactory().NewLogger("turn")
	ts, err := turn.NewServer(turn.ServerConfig{
		Realm:       realm,
		AuthHandler: turn.NewLongTermAuthHandler(cfg.Secret, logger),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: ip,
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay: start TURN server: %w", err)
	}

	return &Server{
		turn:     ts,
		conn:     conn,
		publicIP: cfg.PublicIP,
		port:     port,
		realm:    realm,
		secret:   cfg.Secret,
		ttl:      ttl,
	}, nil
}

// Issue mints one set of ephemeral TURN credentials for a peer.
func (s *Server) Issue(_ time.Duration) (signal.TURNCred, bool) {
	username, password, err := turn.GenerateLongTermCredentials(s.secret, s.ttl)
	if err != nil {
		return signal.TURNCred{}, false
	}
	return signal.TURNCred{
		URL:      fmt.Sprintf("turn:%s:%d?transport=udp", s.publicIP, s.port),
		Username: username,
		Password: password,
	}, true
}

// Port returns the UDP port the relay is listening on (useful when :0 was
// requested in tests).
func (s *Server) Port() int { return s.port }

// Close stops the TURN server and releases the socket.
func (s *Server) Close() error {
	err := s.turn.Close()
	_ = s.conn.Close()
	return err
}
