// Package xcrypto holds the TLS identity machinery for xtunnel sessions.
//
// Each peer generates an ephemeral self-signed certificate; authentication
// comes from pinning the SHA-256 fingerprint of the peer's leaf certificate,
// which is delivered out of band (inside the manual pairing blob, or over the
// PAKE-protected signaling channel in rendezvous mode). The certificate chain
// itself is never trusted.
package xcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ALPN is the application protocol negotiated on every xtunnel QUIC session.
// Bump the suffix on incompatible wire-protocol changes.
const ALPN = "xtunnel/1"

// Fingerprint is the SHA-256 digest of a peer's leaf certificate in DER form.
type Fingerprint [32]byte

func (f Fingerprint) String() string { return fmt.Sprintf("%x", f[:]) }

// GenerateCert creates an ephemeral self-signed ECDSA P-256 certificate for
// one tunnel session and returns it with its fingerprint.
func GenerateCert() (tls.Certificate, Fingerprint, error) {
	var fp Fingerprint

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fp, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fp, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xtunnel"},
		DNSNames:              []string{"xtunnel"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fp, fmt.Errorf("create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fp, fmt.Errorf("parse certificate: %w", err)
	}

	fp = sha256.Sum256(der)
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return cert, fp, nil
}

// ErrFingerprintMismatch is returned during the TLS handshake when the peer
// presented a certificate whose digest does not match the pinned fingerprint.
var ErrFingerprintMismatch = errors.New("peer certificate fingerprint mismatch")

func pinVerifier(expected Fingerprint) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		if got != expected {
			return fmt.Errorf("%w: got %x want %x", ErrFingerprintMismatch, got[:8], expected[:8])
		}
		return nil
	}
}

// ClientTLS builds the TLS config for the QUIC-dialing side, pinning the
// remote peer's certificate to expected.
func ClientTLS(cert tls.Certificate, expected Fingerprint) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{ALPN},
		ServerName:         "xtunnel",
		InsecureSkipVerify: true, // chain trust replaced by fingerprint pinning below
		VerifyPeerCertificate: pinVerifier(expected),
	}
}

// ServerTLS builds the TLS config for the QUIC-listening side. The client is
// required to present a certificate, which is pinned to expected (mutual
// authentication).
func ServerTLS(cert tls.Certificate, expected Fingerprint) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		NextProtos:            []string{ALPN},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinVerifier(expected),
	}
}
