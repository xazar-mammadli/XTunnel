package relay

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/xazar-mammadli/XTunnel/internal/signal"
)

type Config struct {
	PublicIP      string
	ListenAddr    string
	Realm         string
	Secret        string
	CredentialTTL time.Duration
}

type Server struct {
	turn     *turn.Server
	conn     net.PacketConn
	publicIP string
	port     int
	realm    string
	secret   string
	ttl      time.Duration
}

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

func (s *Server) Port() int { return s.port }

func (s *Server) Close() error {
	err := s.turn.Close()
	_ = s.conn.Close()
	return err
}
