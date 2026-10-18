package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

var appVersion = "dev"

var defaultServer = "wss://xtunnel-relay.xazar-mammadli.workers.dev"

const usageText = `XTunnel shares TCP ports between two machines over an encrypted peer-to-peer tunnel.

Usage:
  xtunnel share <port>...               share local ports and print a one-time code
  xtunnel connect <code> [forward]...   connect to the machine that printed the code
  xtunnel version

Forwards for connect:
  (none)             every shared port, on the same local port
  5432               127.0.0.1:5432 -> remote port 5432
  15432:5432         127.0.0.1:15432 -> remote port 5432
  0.0.0.0:8080:80    0.0.0.0:8080 -> remote port 80

Flags:
  --server <url>          signaling server (default: the public relay, or XTUNNEL_SERVER)
  --offline               pair by copy-pasting codes, without any server
  --timeout <duration>    how long to wait for the other side (default 10m)
  --stun <uri>            STUN server, repeatable
  --turn <url,user,pass>  TURN relay, repeatable
  --no-retry              do not reconnect after a drop (self-hosted xtunneld)
  -v                      verbose output

Examples:
  xtunnel share 5432
  xtunnel share 5432 8080 3000
  xtunnel connect 47-905183
  xtunnel connect 47-905183 15432:5432 18080:8080
`

func main() {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	log.SetOutput(io.Discard)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "share":
		err = runShare(args)
	case "connect":
		err = runConnect(args)
	case "version", "--version":
		fmt.Println(appVersion)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usageText)
		os.Exit(2)
	}

	var ue usageError
	switch {
	case err == nil:
	case errors.Is(err, errHelp):
		fmt.Print(usageText)
	case errors.As(err, &ue):
		fmt.Fprintf(os.Stderr, "error: %s\nRun 'xtunnel help' for usage.\n", ue)
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "error: %s\n", friendly(err))
		os.Exit(1)
	}
}
