// Command xtunneld is the self-hosted xtunnel rendezvous server. One process
// provides three services:
//
//   - a WebSocket mailbox (one-time room codes; relays only PAKE/AEAD
//     ciphertext between paired peers)
//   - STUN, so peers can discover their public addresses  (milestone M5)
//   - a TURN relay as fallback when hole punching fails    (milestone M5)
//
// It keeps all state in memory and never sees tunnel plaintext.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/xazar/xtunnel/internal/mailbox"
)

var appVersion = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	var (
		listen  = flag.String("listen", ":8080", "HTTP/WebSocket listen address")
		tlsCert = flag.String("tls-cert", "", "TLS certificate file (serve wss:// directly)")
		tlsKey  = flag.String("tls-key", "", "TLS key file")
		version = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println(appVersion)
		return
	}

	mb := mailbox.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", mb.HandleWS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("both --tls-cert and --tls-key are required for TLS")
		}
		log.Printf("xtunneld %s: mailbox listening on %s (wss)", appVersion, *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("xtunneld %s: mailbox listening on %s (ws, plaintext — put wss termination in front for production)", appVersion, *listen)
	log.Fatal(srv.ListenAndServe())
}
