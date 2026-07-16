// Command xtunnel is the peer CLI: it establishes an encrypted peer-to-peer
// QUIC tunnel across NATs and forwards TCP ports through it.
package main

import (
	"fmt"
	"log"
	"os"
)

// appVersion is stamped by -ldflags "-X main.appVersion=..." at release time.
var appVersion = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `xtunnel — peer-to-peer encrypted TCP port forwarding across NATs

Usage:
  xtunnel <command> [flags]

Serverless pairing with one code (signaling via a public broker, no server to run):
  xtunnel offer  --expose <port>                share ports, print one pairing code
  xtunnel answer <code> -L <local:remote> ...   type that code, connect
     add --offline to both sides for two-way copy-paste with no broker at all

Rendezvous pairing (via a self-hosted xtunneld server; adds relay fallback):
  xtunnel host --server <wss-url> --expose <port> ...
  xtunnel join <room-code> --server <wss-url> -L <local:remote> ...

Other:
  xtunnel version

Common flags:
  --expose <port>          (offer/host, repeatable) local TCP port to share
  -L <[local:]remote>      (answer/join, repeatable) forward 127.0.0.1:<local>
                           to the peer's <remote> port; -L 8080 uses the same
                           port on both sides; a bind address may be given as
                           -L 0.0.0.0:8080:80
  --signal-url <url>       (offer/answer) public signaling broker (default ntfy.sh)
  --offline                (offer/answer) use copy-paste blobs, no broker
  --stun <uri>             (repeatable) STUN server, default: Google+Cloudflare
  --turn <url,user,pass>   (repeatable) TURN relay for hard NATs
`)
}

func main() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stderr)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "offer":
		err = runOffer(args)
	case "answer":
		err = runAnswer(args)
	case "host":
		err = runHost(args)
	case "join":
		err = runJoin(args)
	case "version":
		fmt.Println(appVersion)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}
