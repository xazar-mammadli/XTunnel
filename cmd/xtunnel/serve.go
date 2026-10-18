package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/xazar-mammadli/XTunnel/internal/peer"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

func serveHost(ctx context.Context, sess *peer.Session, ports []uint16, out *console) error {
	defer sess.Close()
	out.say("Sharing %s. Press Ctrl+C to stop.", portsText(ports))
	return endOfTunnel(ctx, tunnel.ServeHost(ctx, sess.Conn, ports, out.logf()))
}

func serveJoiner(ctx context.Context, sess *peer.Session, forwards []tunnel.Forward, out *console) error {
	defer sess.Close()
	j, err := tunnel.StartJoin(ctx, sess.Conn, forwards, out.logf())
	if err != nil {
		return err
	}
	defer j.Close()
	addrs := j.Addrs()
	for i, f := range j.Forwards() {
		out.say("Forwarding %s -> remote port %d", addrs[i], f.Port)
	}
	out.say("Press Ctrl+C to stop.")

	done := make(chan error, 1)
	go func() { done <- j.Wait() }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-done:
		return endOfTunnel(ctx, err)
	}
}

func endOfTunnel(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return nil
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.Remote {
		return errPeerClosed
	}
	return fmt.Errorf("%w: %v", errConnectionLost, err)
}

func finish(err error, out *console) error {
	if errors.Is(err, errPeerClosed) {
		out.say("The other side closed the tunnel.")
		return nil
	}
	return err
}
