// Package blob implements the compact copy-paste pairing code used by manual
// (serverless) mode.
//
// Raw layout, base64url-encoded (no padding) behind the "xt1_" prefix:
//
//	[1B  version<<4 | flags]   flags bit0: 1 = answer blob
//	[16B seed]                 ICE ufrag/pwd are HKDF-derived from this
//	[32B TLS cert SHA-256 fingerprint]
//	[1B  candidate count]
//	per candidate:
//	  [1B  flags]              bit0: 1 = IPv6
//	  [4B or 16B IP]
//	  [2B port, big endian]
//
// ICE credentials are never transmitted: both sides derive the same values
// from the seed, which keeps typical blobs under ~120 characters.
package blob

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/pion/ice/v4"

	"github.com/xazar/xtunnel/internal/xcrypto"
)

// Prefix marks (and versions) the printable form of a pairing code.
const Prefix = "xt1_"

const version = 1

const maxCandidates = 8

// Candidate is one reachable UDP endpoint of the sending peer.
type Candidate struct {
	Addr netip.Addr
	Port uint16
}

// Blob is one direction of the manual pairing exchange.
type Blob struct {
	IsAnswer    bool
	Seed        [16]byte
	Fingerprint xcrypto.Fingerprint
	Candidates  []Candidate
}

// NewSeed returns 16 bytes of cryptographic randomness.
func NewSeed() ([16]byte, error) {
	var s [16]byte
	_, err := rand.Read(s[:])
	return s, err
}

// DeriveICECredentials expands a blob seed into the ICE ufrag (16 chars) and
// pwd (24 chars). The base64 alphabet is a subset of RFC 8839 ice-char.
func DeriveICECredentials(seed [16]byte) (ufrag, pwd string, err error) {
	uk, err := hkdf.Key(sha256.New, seed[:], nil, "xtunnel/ice-ufrag", 12)
	if err != nil {
		return "", "", err
	}
	pk, err := hkdf.Key(sha256.New, seed[:], nil, "xtunnel/ice-pwd", 18)
	if err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(uk), base64.RawStdEncoding.EncodeToString(pk), nil
}

// Encode renders the printable pairing code.
func (b *Blob) Encode() string {
	raw := make([]byte, 0, 50+18*len(b.Candidates))
	flags := byte(0)
	if b.IsAnswer {
		flags |= 1
	}
	raw = append(raw, version<<4|flags)
	raw = append(raw, b.Seed[:]...)
	raw = append(raw, b.Fingerprint[:]...)

	cands := b.Candidates
	if len(cands) > maxCandidates {
		cands = cands[:maxCandidates]
	}
	raw = append(raw, byte(len(cands)))
	for _, c := range cands {
		if c.Addr.Is4() {
			raw = append(raw, 0)
			a4 := c.Addr.As4()
			raw = append(raw, a4[:]...)
		} else {
			raw = append(raw, 1)
			a16 := c.Addr.As16()
			raw = append(raw, a16[:]...)
		}
		raw = append(raw, byte(c.Port>>8), byte(c.Port))
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// Decode parses a printable pairing code.
func Decode(s string) (*Blob, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return nil, fmt.Errorf("pairing code must start with %q", Prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		return nil, fmt.Errorf("malformed pairing code: %w", err)
	}
	if len(raw) < 1+16+32+1 {
		return nil, errors.New("pairing code too short")
	}
	if raw[0]>>4 != version {
		return nil, fmt.Errorf("unsupported pairing code version %d", raw[0]>>4)
	}
	b := &Blob{IsAnswer: raw[0]&1 == 1}
	off := 1
	off += copy(b.Seed[:], raw[off:off+16])
	off += copy(b.Fingerprint[:], raw[off:off+32])
	n := int(raw[off])
	off++
	if n > maxCandidates {
		return nil, fmt.Errorf("too many candidates: %d", n)
	}
	for i := 0; i < n; i++ {
		if off >= len(raw) {
			return nil, errors.New("truncated candidate list")
		}
		ipLen := 4
		if raw[off]&1 == 1 {
			ipLen = 16
		}
		off++
		if off+ipLen+2 > len(raw) {
			return nil, errors.New("truncated candidate")
		}
		addr, ok := netip.AddrFromSlice(raw[off : off+ipLen])
		if !ok {
			return nil, errors.New("invalid candidate address")
		}
		off += ipLen
		port := uint16(raw[off])<<8 | uint16(raw[off+1])
		off += 2
		b.Candidates = append(b.Candidates, Candidate{Addr: addr, Port: port})
	}
	if off != len(raw) {
		return nil, errors.New("trailing bytes in pairing code")
	}
	return b, nil
}

// PackCandidates converts gathered local ICE candidates into blob form:
// host + server-reflexive only, de-duplicated, link-local and unspecified
// addresses dropped, capped at maxCandidates. Loopback is kept so two
// processes on one machine can pair during testing.
func PackCandidates(cands []ice.Candidate) []Candidate {
	seen := make(map[Candidate]bool)
	var out []Candidate
	for _, c := range cands {
		switch c.Type() {
		case ice.CandidateTypeHost, ice.CandidateTypeServerReflexive:
		default:
			continue
		}
		addr, err := netip.ParseAddr(c.Address())
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
			continue
		}
		k := Candidate{Addr: addr, Port: uint16(c.Port())}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) == maxCandidates {
			break
		}
	}
	return out
}

// ToICECandidates converts received blob candidates into remote ICE
// candidates. All are presented as host type: for connectivity checks the
// type only influences priority, not reachability.
func ToICECandidates(cands []Candidate) ([]ice.Candidate, error) {
	out := make([]ice.Candidate, 0, len(cands))
	for _, c := range cands {
		ic, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
			Network:   "udp",
			Address:   c.Addr.String(),
			Port:      int(c.Port),
			Component: ice.ComponentRTP, // component 1; xtunnel uses a single component
		})
		if err != nil {
			return nil, fmt.Errorf("candidate %s:%d: %w", c.Addr, c.Port, err)
		}
		out = append(out, ic)
	}
	return out, nil
}
