package main

import (
	"context"
	"errors"
	"log"

	"github.com/pion/ice/v4"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/peer"
	"github.com/xazar/xtunnel/internal/tunnel"
)

// logICEStates attaches human-readable ICE progress logging.
func logICEStates(ep *icewrap.Endpoint) {
	_ = ep.OnConnectionStateChange(func(s ice.ConnectionState) {
		log.Printf("ICE: %s", s)
	})
}

// printPath reports whether the nominated path is direct or relayed.
func printPath(ep *icewrap.Endpoint) {
	pair, err := ep.SelectedPair()
	if err != nil || pair == nil {
		return
	}
	kind := "direct P2P"
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		kind = "relayed via TURN"
	}
	log.Printf("path: %s (%s:%d <-> %s:%d)",
		kind, pair.Local.Address(), pair.Local.Port(), pair.Remote.Address(), pair.Remote.Port())
}

// serveAsHost runs the host data plane until the connection or ctx dies.
func serveAsHost(ctx context.Context, sess *peer.Session, expose []uint16) error {
	defer sess.Close()
	log.Printf("tunnel established — exposing ports %v", expose)
	err := tunnel.ServeHost(ctx, sess.Conn, expose, log.Printf)
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		log.Printf("shutting down")
		return nil
	}
	return err
}

// serveAsJoiner runs the joiner data plane until the connection or ctx dies.
func serveAsJoiner(ctx context.Context, sess *peer.Session, forwards []tunnel.Forward) error {
	defer sess.Close()
	j, err := tunnel.StartJoin(ctx, sess.Conn, forwards, log.Printf)
	if err != nil {
		return err
	}
	defer j.Close()
	log.Printf("tunnel established — host exposes ports %v", j.RemotePorts())

	done := make(chan error, 1)
	go func() { done <- j.Wait() }()
	select {
	case <-ctx.Done():
		log.Printf("shutting down")
		return nil
	case err := <-done:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}
