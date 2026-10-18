package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

var (
	errWaitTimeout    = errors.New("nobody connected before the timeout")
	errNoPath         = errors.New("no network path between the machines")
	errConnectionLost = errors.New("the connection to the other side was lost")
	errPeerClosed     = errors.New("the other side closed the tunnel")
)

func friendly(err error) string {
	var dialErr *sig.DialError
	var srvErr *sig.ServerError
	var lnErr *tunnel.ListenError
	switch {
	case errors.As(err, &dialErr) && dialErr.Status == http.StatusTooManyRequests:
		return "the signaling server is busy or has reached its daily limit; try again later, or use --server <url> or --offline"
	case errors.As(err, &dialErr) && dialErr.Body != "" && dialErr.Status >= 400 && dialErr.Status < 500:
		return serverMessage(dialErr.Body)
	case errors.As(err, &dialErr) && dialErr.Status != 0:
		return fmt.Sprintf("the signaling server %s refused the connection (HTTP %d)", dialErr.Server, dialErr.Status)
	case errors.As(err, &dialErr):
		return fmt.Sprintf("cannot reach the signaling server %s (%v)", dialErr.Server, rootCause(dialErr.Err))
	case errors.As(err, &srvErr):
		return serverMessage(srvErr.Msg)
	case errors.Is(err, sig.ErrWrongCode):
		return "wrong code, or someone else tried to use it; ask for a new code"
	case errors.Is(err, sig.ErrPeerLeft):
		return "the other side disconnected before the tunnel was ready (a mistyped code causes this); ask for a new code"
	case errors.Is(err, errNoPath):
		return "could not connect the two machines (strict NAT or firewall); a self-hosted xtunneld with TURN can relay the traffic, see --server"
	case errors.As(err, &lnErr):
		return fmt.Sprintf("cannot listen on %s (%v); use another local port, e.g. xtunnel connect <code> %d:%d", lnErr.Addr, rootCause(lnErr.Err), altPort(lnErr.Port), lnErr.Port)
	case errors.Is(err, errConnectionLost):
		return errConnectionLost.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	}
	return err.Error()
}

func serverMessage(msg string) string {
	switch {
	case strings.HasPrefix(msg, "no such room"):
		return "this code does not exist or has expired; ask for a new one"
	case msg == "room is full", msg == "room is closed", msg == "room creator is gone":
		return "this code was already used; ask for a new one"
	case msg == "room expired":
		return "the code expired; run 'xtunnel share' again"
	case msg == "rate limited":
		return "too many attempts from your network; wait a minute and try again"
	}
	return "signaling server: " + msg
}

func rootCause(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err
	}
	return err
}

func altPort(p uint16) int {
	if int(p)+10000 <= 65535 {
		return int(p) + 10000
	}
	return int(p) - 10000
}
