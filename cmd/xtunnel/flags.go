package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

var defaultSTUN = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

var errHelp = errors.New("help requested")

type usageError string

func (e usageError) Error() string { return string(e) }

type options struct {
	server          string
	offline         bool
	timeout         time.Duration
	stun            stringList
	turn            turnList
	noRetry         bool
	verbose         bool
	includeLoopback bool
	forceRelay      bool
}

func newFlagSet(name string, o *options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.server, "server", "", "")
	fs.BoolVar(&o.offline, "offline", false, "")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Minute, "")
	fs.Var(&o.stun, "stun", "")
	fs.Var(&o.turn, "turn", "")
	fs.BoolVar(&o.noRetry, "no-retry", false, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.includeLoopback, "include-loopback", false, "")
	fs.BoolVar(&o.forceRelay, "force-relay", false, "")
	return fs
}

func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelp
			}
			return nil, usageError(err.Error())
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func (o *options) serverURL() (string, error) {
	switch {
	case o.server != "":
		return o.server, nil
	case os.Getenv("XTUNNEL_SERVER") != "":
		return os.Getenv("XTUNNEL_SERVER"), nil
	case defaultServer != "":
		return defaultServer, nil
	}
	return "", usageError("no signaling server configured: use --server <url>, set XTUNNEL_SERVER, or pair with --offline")
}

func (o *options) stunServers() []string {
	if o.stun != nil {
		return o.stun
	}
	return defaultSTUN
}

func parsePorts(args []string) ([]uint16, error) {
	ports := make([]uint16, 0, len(args))
	seen := make(map[uint16]bool, len(args))
	for _, a := range args {
		p, err := parsePort(a)
		if err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func parseForwards(args []string) ([]tunnel.Forward, error) {
	forwards := make([]tunnel.Forward, 0, len(args))
	for _, a := range args {
		f, err := parseForward(a)
		if err != nil {
			return nil, err
		}
		forwards = append(forwards, f)
	}
	return forwards, nil
}

func parseForward(s string) (tunnel.Forward, error) {
	parts := strings.Split(s, ":")
	var bind, local, remote string
	switch len(parts) {
	case 1:
		bind, local, remote = "127.0.0.1", parts[0], parts[0]
	case 2:
		bind, local, remote = "127.0.0.1", parts[0], parts[1]
	case 3:
		bind, local, remote = parts[0], parts[1], parts[2]
	default:
		return tunnel.Forward{}, usageError(fmt.Sprintf("invalid forward %q (want port, local:remote or bind:local:remote)", s))
	}
	lp, err := parsePort(local)
	if err != nil {
		return tunnel.Forward{}, err
	}
	rp, err := parsePort(remote)
	if err != nil {
		return tunnel.Forward{}, err
	}
	return tunnel.Forward{Listen: fmt.Sprintf("%s:%d", bind, lp), Port: rp}, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, usageError(fmt.Sprintf("invalid port %q", s))
	}
	return uint16(n), nil
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

type turnList []icewrap.TURNServer

func (l *turnList) String() string {
	parts := make([]string, len(*l))
	for i, t := range *l {
		parts[i] = t.URL
	}
	return strings.Join(parts, " ")
}

func (l *turnList) Set(s string) error {
	parts := strings.SplitN(s, ",", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid --turn %q (want url,username,password)", s)
	}
	*l = append(*l, icewrap.TURNServer{URL: parts[0], Username: parts[1], Password: parts[2]})
	return nil
}
