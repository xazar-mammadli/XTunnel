package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/xazar-mammadli/XTunnel/internal/mailbox"
	"github.com/xazar-mammadli/XTunnel/internal/relay"
)

var appVersion = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	var (
		listen     = flag.String("listen", ":8080", "HTTP/WebSocket listen address")
		tlsCert    = flag.String("tls-cert", "", "TLS certificate file (serve wss:// directly)")
		tlsKey     = flag.String("tls-key", "", "TLS key file")
		turnIP     = flag.String("turn-public-ip", "", "public IPv4 of this server; enables the embedded TURN relay fallback")
		turnListen = flag.String("turn-listen", ":3478", "UDP listen address for the TURN relay")
		turnSecret = flag.String("turn-secret", "", "shared HMAC secret for TURN credentials (random if empty)")
		turnTTL    = flag.Duration("turn-ttl", 24*time.Hour, "lifetime of issued TURN credentials; must exceed the tunnel's expected lifetime so relayed reconnects keep working (creds are issued once at pairing)")
		version    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println(appVersion)
		return
	}

	var issuer mailbox.TURNIssuer
	if *turnIP != "" {
		secret := *turnSecret
		if secret == "" {
			var b [32]byte
			if _, err := rand.Read(b[:]); err != nil {
				log.Fatalf("generate TURN secret: %v", err)
			}
			secret = hex.EncodeToString(b[:])
		}
		rs, err := relay.Start(relay.Config{
			PublicIP:      *turnIP,
			ListenAddr:    *turnListen,
			Secret:        secret,
			CredentialTTL: *turnTTL,
		})
		if err != nil {
			log.Fatalf("start relay: %v", err)
		}
		defer rs.Close()
		issuer = rs
		log.Printf("TURN relay enabled: turn:%s:%d (creds valid %s)", *turnIP, rs.Port(), *turnTTL)
	} else {
		log.Printf("TURN relay disabled (no --turn-public-ip); peers behind symmetric NAT may fail to connect")
	}

	mb := mailbox.New(issuer)

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
