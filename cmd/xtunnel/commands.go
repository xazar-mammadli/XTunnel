package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xazar-mammadli/XTunnel/internal/blob"
	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

func runShare(args []string) error {
	var o options
	positional, err := parseArgs(newFlagSet("share", &o), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usageError("which port should be shared? e.g. xtunnel share 5432")
	}
	ports, err := parsePorts(positional)
	if err != nil {
		return err
	}

	ctx, stop, out := prepare(&o)
	defer stop()
	if o.offline {
		return shareOffline(ctx, &o, ports, out)
	}
	return shareSignaled(ctx, &o, ports, out)
}

func runConnect(args []string) error {
	var o options
	positional, err := parseArgs(newFlagSet("connect", &o), args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return usageError("missing code, e.g. xtunnel connect 47-905183")
	}
	code := strings.TrimSpace(positional[0])
	forwards, err := parseForwards(positional[1:])
	if err != nil {
		return err
	}

	switch {
	case strings.HasPrefix(code, blob.Prefix):
	case o.offline:
		return usageError("offline mode needs the xt1_ code printed by 'xtunnel share --offline'")
	case !sig.ValidCode(code):
		return usageError(fmt.Sprintf("%q is not a valid code (it looks like 47-905183)", code))
	}

	if err := checkListen(forwards); err != nil {
		return err
	}

	ctx, stop, out := prepare(&o)
	defer stop()
	if strings.HasPrefix(code, blob.Prefix) {
		return connectOffline(ctx, &o, code, forwards, out)
	}
	return connectSignaled(ctx, &o, code, forwards, out)
}

func prepare(o *options) (context.Context, context.CancelFunc, *console) {
	if o.verbose {
		log.SetOutput(os.Stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, stop, newConsole(o.verbose)
}

func checkListen(forwards []tunnel.Forward) error {
	for _, f := range forwards {
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			return &tunnel.ListenError{Addr: f.Listen, Port: f.Port, Err: err}
		}
		_ = ln.Close()
	}
	return nil
}
